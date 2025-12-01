package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BolaHunter implements BurpExtension {

    private MontoyaApi api;
    private Logging logging;
    private Preferences preferences;

    // --- DATA STRUCTURES ---
    private static class RegexRule {
        String name;
        String pattern;
        boolean enabled;

        RegexRule(String name, String pattern, boolean enabled) {
            this.name = name;
            this.pattern = pattern;
            this.enabled = enabled;
        }
    }

    private static class CapturedItem {
        final String value;
        final String type;
        final String url;
        final String method;
        final HttpRequest request;

        // Response is NOT final anymore, so we can update it later
        HttpResponse response;
        boolean active;

        CapturedItem(String value, String type, HttpRequest req, HttpResponse res) {
            this.value = value;
            this.type = type;
            this.request = req;
            this.response = res;
            this.url = req.url();
            this.method = req.method();
            this.active = true;
        }
    }

    private static final Map<String, CapturedItem> GLOBAL_POOL = new ConcurrentHashMap<>();
    private static final List<RegexRule> REGEX_RULES = new CopyOnWriteArrayList<>();

    // --- UI COMPONENTS ---
    private JToggleButton tglActive;
    private ResultsTableModel resultsModel;
    private SettingsTableModel settingsModel;
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.preferences = api.persistence().preferences();

        api.extension().setName("Context-Aware BOLA Hunter v12 (Full Traffic)");

        loadRulesFromStorage();
        if (REGEX_RULES.isEmpty()) loadDefaultRules();

        Component mainTab = createMainUi();
        api.userInterface().registerSuiteTab("BOLA Hunter", mainTab);
        api.http().registerHttpHandler(new BolaHandler());

        logging.logToOutput("BOLA Hunter v12 Loaded.");
    }

    private void loadRulesFromStorage() {
        REGEX_RULES.clear();
        String countStr = preferences.getString("Rule_Count");
        if (countStr != null) {
            try {
                int count = Integer.parseInt(countStr);
                for (int i = 0; i < count; i++) {
                    String name = preferences.getString("Rule_" + i + "_Name");
                    String pattern = preferences.getString("Rule_" + i + "_Pattern");
                    String enabledStr = preferences.getString("Rule_" + i + "_Enabled");
                    if (name != null && pattern != null) {
                        REGEX_RULES.add(new RegexRule(name, pattern, Boolean.parseBoolean(enabledStr)));
                    }
                }
            } catch (Exception e) {}
        }
    }

    private void saveRulesToStorage() {
        preferences.setString("Rule_Count", String.valueOf(REGEX_RULES.size()));
        for (int i = 0; i < REGEX_RULES.size(); i++) {
            RegexRule rule = REGEX_RULES.get(i);
            preferences.setString("Rule_" + i + "_Name", rule.name);
            preferences.setString("Rule_" + i + "_Pattern", rule.pattern);
            preferences.setString("Rule_" + i + "_Enabled", String.valueOf(rule.enabled));
        }
    }

    private void loadDefaultRules() {
        REGEX_RULES.clear();
        REGEX_RULES.add(new RegexRule("UUID", "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", true));
        REGEX_RULES.add(new RegexRule("Email", "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}", true));
        REGEX_RULES.add(new RegexRule("Int ID", "\\b[0-9]{4,10}\\b", true));
        REGEX_RULES.add(new RegexRule("User Ref", "usr_[a-zA-Z0-9]+", true));
        saveRulesToStorage();
    }

    // --- UI CONSTRUCTION ---
    class ResultsTableModel extends DefaultTableModel {
        public ResultsTableModel(Object[] columnNames, int rowCount) { super(columnNames, rowCount); }
        public Class<?> getColumnClass(int columnIndex) { return columnIndex == 0 ? Boolean.class : String.class; }
        public boolean isCellEditable(int row, int column) { return column == 0; }
        public void setValueAt(Object aValue, int row, int column) {
            super.setValueAt(aValue, row, column);
            if (column == 0) {
                String val = (String) getValueAt(row, 1);
                CapturedItem item = GLOBAL_POOL.get(val);
                if (item != null) item.active = (Boolean) aValue;
            }
        }
    }

    private Component createMainUi() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Live Hunt", createResultsTab());
        tabs.addTab("Settings", createSettingsTab());
        return tabs;
    }

    private Component createResultsTab() {
        JPanel pnlControls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        tglActive = new JToggleButton("ATTACK MODE: OFF");
        tglActive.setBackground(Color.RED);
        tglActive.setForeground(Color.WHITE);
        tglActive.addActionListener(e -> {
            if (tglActive.isSelected()) {
                tglActive.setText("ATTACK MODE: ON");
                tglActive.setBackground(Color.GREEN);
                tglActive.setForeground(Color.BLACK);
            } else {
                tglActive.setText("ATTACK MODE: OFF");
                tglActive.setBackground(Color.RED);
                tglActive.setForeground(Color.WHITE);
            }
        });

        JButton btnDelete = new JButton("Delete Selected");
        JButton btnClear = new JButton("Clear All");
        btnClear.addActionListener(e -> {
            GLOBAL_POOL.clear();
            resultsModel.setRowCount(0);
            requestViewer.setRequest(null);
            responseViewer.setResponse(null);
        });

        pnlControls.add(tglActive);
        pnlControls.add(Box.createRigidArea(new Dimension(10, 0)));
        pnlControls.add(btnDelete);
        pnlControls.add(btnClear);

        String[] columns = {"Use", "Captured Value", "Type", "Method", "Source URL"};
        resultsModel = new ResultsTableModel(columns, 0);
        JTable table = new JTable(resultsModel);
        table.getColumnModel().getColumn(0).setMaxWidth(50);
        JScrollPane tableScroll = new JScrollPane(table);

        requestViewer = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseViewer = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        JSplitPane editorSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestViewer.uiComponent(), responseViewer.uiComponent());
        editorSplit.setResizeWeight(0.5);

        Runnable deleteAction = () -> {
            int row = table.getSelectedRow();
            if (row != -1) {
                String valueToDelete = (String) resultsModel.getValueAt(row, 1);
                GLOBAL_POOL.remove(valueToDelete);
                resultsModel.removeRow(row);
                requestViewer.setRequest(null);
                responseViewer.setResponse(null);
            }
        };
        btnDelete.addActionListener(e -> deleteAction.run());

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && table.getSelectedRow() != -1) {
                String selectedVal = (String) resultsModel.getValueAt(table.getSelectedRow(), 1);
                CapturedItem item = GLOBAL_POOL.get(selectedVal);
                if (item != null) {
                    requestViewer.setRequest(item.request);
                    responseViewer.setResponse(item.response); // This might be null if not updated!
                    requestViewer.setSearchExpression(selectedVal);
                    responseViewer.setSearchExpression(selectedVal);
                }
            }
        });

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, editorSplit);
        mainSplit.setDividerLocation(300);
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(pnlControls, BorderLayout.NORTH);
        mainPanel.add(mainSplit, BorderLayout.CENTER);
        return mainPanel;
    }

    class SettingsTableModel extends DefaultTableModel {
        public SettingsTableModel(Object[] columnNames, int rowCount) { super(columnNames, rowCount); }
        public Class<?> getColumnClass(int columnIndex) { return columnIndex == 0 ? Boolean.class : String.class; }
        public boolean isCellEditable(int row, int column) { return column == 0; }
        public void setValueAt(Object aValue, int row, int column) {
            super.setValueAt(aValue, row, column);
            if (column == 0 && row < REGEX_RULES.size()) {
                REGEX_RULES.get(row).enabled = (Boolean) aValue;
                saveRulesToStorage();
            }
        }
    }

    private Component createSettingsTab() {
        JPanel mainPanel = new JPanel(new BorderLayout());
        String[] columns = {"Active", "Rule Name", "Regex Pattern"};
        settingsModel = new SettingsTableModel(columns, 0);
        refreshSettingsTable();
        JTable settingsTable = new JTable(settingsModel);
        settingsTable.getColumnModel().getColumn(0).setMaxWidth(60);
        JScrollPane scroll = new JScrollPane(settingsTable);

        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL; gbc.insets = new Insets(5, 5, 5, 5);

        JTextField txtName = new JTextField(15);
        JTextField txtPattern = new JTextField(30);

        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.0; formPanel.add(new JLabel("Rule Name:"), gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0; formPanel.add(txtName, gbc);
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0; formPanel.add(new JLabel("Regex Pattern:"), gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0; formPanel.add(txtPattern, gbc);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton btnAdd = new JButton("Add Rule");
        JButton btnReset = new JButton("Reset to Defaults");

        btnAdd.addActionListener(e -> {
            String name = txtName.getText().trim(); String pat = txtPattern.getText().trim();
            if (!name.isEmpty() && !pat.isEmpty()) {
                REGEX_RULES.add(new RegexRule(name, pat, true));
                settingsModel.addRow(new Object[]{true, name, pat});
                saveRulesToStorage();
                txtName.setText(""); txtPattern.setText("");
            }
        });
        btnReset.addActionListener(e -> { loadDefaultRules(); refreshSettingsTable(); });
        buttonPanel.add(btnReset); buttonPanel.add(btnAdd);

        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2; formPanel.add(buttonPanel, gbc);
        mainPanel.add(new JLabel("  Toggle rules on/off using the checkbox."), BorderLayout.NORTH);
        mainPanel.add(scroll, BorderLayout.CENTER);
        mainPanel.add(formPanel, BorderLayout.SOUTH);
        return mainPanel;
    }

    private void refreshSettingsTable() {
        settingsModel.setRowCount(0);
        for (RegexRule rule : REGEX_RULES) settingsModel.addRow(new Object[]{rule.enabled, rule.name, rule.pattern});
    }

    // --- LOGIC ENGINE ---
    class BolaHandler implements HttpHandler {
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
            String path = requestToBeSent.path();

            // 1. HARVEST FROM URL (Request Phase)
            for (RegexRule rule : REGEX_RULES) {
                if (!rule.enabled) continue;
                Matcher matcher = Pattern.compile(rule.pattern).matcher(path);
                while (matcher.find()) {
                    String foundVal = matcher.group();
                    if (!GLOBAL_POOL.containsKey(foundVal)) {
                        // Store with Null Response initially
                        CapturedItem item = new CapturedItem(foundVal, rule.name, requestToBeSent, null);
                        GLOBAL_POOL.put(foundVal, item);
                        SwingUtilities.invokeLater(() -> {
                            resultsModel.addRow(new Object[]{true, item.value, item.type, item.method, item.url});
                        });
                        logging.logToOutput("[*] HARVESTED from Request URL: " + foundVal);
                    }
                }
            }

            // 2. ATTACK LOGIC
            if (!tglActive.isSelected()) return RequestToBeSentAction.continueWith(requestToBeSent);
            if (requestToBeSent.toolSource().isFromTool(ToolType.REPEATER)) return RequestToBeSentAction.continueWith(requestToBeSent);
            if (GLOBAL_POOL.isEmpty()) return RequestToBeSentAction.continueWith(requestToBeSent);

            // Path Injection
            for (RegexRule rule : REGEX_RULES) {
                if (!rule.enabled) continue;
                Matcher matcher = Pattern.compile(rule.pattern).matcher(path);
                if (matcher.find()) {
                    String foundInPath = matcher.group();
                    for (CapturedItem item : GLOBAL_POOL.values()) {
                        if (!item.active) continue;
                        if (item.value.matches(rule.pattern) && !foundInPath.equals(item.value)) {
                            logging.logToOutput("[+] PATH ATTACK: Replaced " + foundInPath + " with " + item.value);
                            String newPath = path.replace(foundInPath, item.value);
                            return RequestToBeSentAction.continueWith(requestToBeSent.withPath(newPath));
                        }
                    }
                }
            }

            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
            String body = responseReceived.bodyToString();
            HttpRequest initiatingRequest = responseReceived.initiatingRequest();
            String path = initiatingRequest.path(); // The URL that triggered this

            // --- 1. BACKFILL RESPONSES ---
            // Did we capture an ID from the Request URL earlier? If so, fill in the Response now.
            for (RegexRule rule : REGEX_RULES) {
                if (!rule.enabled) continue;
                Matcher matcher = Pattern.compile(rule.pattern).matcher(path);
                while (matcher.find()) {
                    String foundInUrl = matcher.group();
                    CapturedItem item = GLOBAL_POOL.get(foundInUrl);
                    // If we have the item but it has no response, update it!
                    if (item != null && item.response == null) {
                        item.response = responseReceived;
                        logging.logToOutput("[*] UPDATED Response for ID: " + foundInUrl);
                    }
                }
            }

            // --- 2. HARVEST FROM BODY ---
            for (RegexRule rule : REGEX_RULES) {
                if (!rule.enabled) continue;
                try {
                    Matcher matcher = Pattern.compile(rule.pattern).matcher(body);
                    while (matcher.find()) {
                        String foundVal = matcher.group();
                        if (!GLOBAL_POOL.containsKey(foundVal)) {
                            CapturedItem item = new CapturedItem(foundVal, rule.name, initiatingRequest, responseReceived);
                            GLOBAL_POOL.put(foundVal, item);
                            logging.logToOutput("[*] HARVESTED from Body (" + rule.name + "): " + foundVal);
                            SwingUtilities.invokeLater(() -> {
                                resultsModel.addRow(new Object[]{true, item.value, item.type, item.method, item.url});
                            });
                        }
                    }
                } catch (Exception e) {}
            }
            return ResponseReceivedAction.continueWith(responseReceived);
        }
    }
}