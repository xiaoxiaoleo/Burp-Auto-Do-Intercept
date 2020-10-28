package burp;

import org.apache.commons.text.StringEscapeUtils;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;
import java.util.List;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab
{
    // make sure to update version in build.gradle as well
    private static final String EXTENSION_VERSION = "0.1.0";

    private static final String SETTING_LOG_LEVEL = "LogLevel";

    public static final String EXTENSION_NAME = "Burp Auto Do Intercept"; // Name in extender menu
    public static final String DISPLAY_NAME = "Auto Intercept"; // name for tabs, menu, and other UI components

    private static PrintWriter stdout;

    protected IExtensionHelpers helpers;
    protected IBurpExtenderCallbacks callbacks;
    private HashMap<String, String> profileUrlPatternMap; // map UrlPattern to profile
    private HashMap<String, ReplaceRule> interceptRuleMap; // map name to profile
    protected LogWriter logger = LogWriter.getLogger();

    private JLabel statusLabel;
    private JCheckBox signingEnabledCheckBox;
    private JComboBox<Object> logLevelComboBox;
    private JTable profileTable;
    private JScrollPane outerScrollPane;

    // mimic burp colors
    protected static final Color textOrange = new Color(255, 102, 51);
    protected static final Color darkOrange = new Color(226, 73, 33);

    private static BurpExtender burpInstance;

    public static BurpExtender getBurp()
    {
        return burpInstance;
    }

    public BurpExtender() {}

    private void buildUiTab()
    {
        final Font sectionFont = new JLabel().getFont().deriveFont(Font.BOLD, 15);

        //
        // global settings, checkboxes
        //
        JPanel globalSettingsPanel = new JPanel();
        globalSettingsPanel.setLayout(new GridBagLayout());
        JLabel settingsLabel = new JLabel("Settings");
        settingsLabel.setForeground(BurpExtender.textOrange);
        settingsLabel.setFont(sectionFont);
        JPanel checkBoxPanel = new JPanel();
        signingEnabledCheckBox = new JCheckBox("Intercept Response Enabled");
        signingEnabledCheckBox.setToolTipText("Enable Auto Intercept Response");
        checkBoxPanel.add(signingEnabledCheckBox);
        JPanel otherSettingsPanel = new JPanel();
        logLevelComboBox = new JComboBox<>();
        otherSettingsPanel.add(new JLabel("Log Level"));
        otherSettingsPanel.add(logLevelComboBox);


        GridBagConstraints c00 = new GridBagConstraints(); c00.anchor = GridBagConstraints.FIRST_LINE_START; c00.gridy = 0; c00.gridwidth = 2;
        GridBagConstraints c01 = new GridBagConstraints(); c01.anchor = GridBagConstraints.FIRST_LINE_START; c01.gridy = 1; c01.gridwidth = 2; c01.insets = new Insets(10, 0, 10, 0);
        GridBagConstraints c02 = new GridBagConstraints(); c02.anchor = GridBagConstraints.FIRST_LINE_START; c02.gridy = 2;
        GridBagConstraints c03 = new GridBagConstraints(); c03.anchor = GridBagConstraints.FIRST_LINE_START; c03.gridy = 3;

        globalSettingsPanel.add(settingsLabel, c00);
        globalSettingsPanel.add(new JLabel("<html>Change plugin behavior. </html>"), c01);
        globalSettingsPanel.add(checkBoxPanel, c02);
        globalSettingsPanel.add(otherSettingsPanel, c03);

        //
        // status label
        //
        JPanel statusPanel = new JPanel();
        statusLabel = new JLabel();
        statusPanel.add(statusLabel);

        //
        // profiles table
        //
        JPanel profilePanel = new JPanel(new GridBagLayout());
        JLabel profileLabel = new JLabel("Intercept Response Rules");
        profileLabel.setForeground(BurpExtender.textOrange);
        profileLabel.setFont(sectionFont);

        JButton addReplaceRuleButton = new JButton("Add");
        JButton editProfileButton = new JButton("Edit");
        JButton removeProfileButton = new JButton("Remove");
        JPanel profileButtonPanel = new JPanel(new GridLayout(7, 1));
        profileButtonPanel.add(addReplaceRuleButton);
        profileButtonPanel.add(editProfileButton);
        profileButtonPanel.add(removeProfileButton);

        final String[] profileColumnNames = {"Name", "URL ", "New Body", "New Header", "Is Enable"};
        profileTable = new JTable(new DefaultTableModel(profileColumnNames, 0)
        {
            @Override
            public boolean isCellEditable(int row, int column)
            {
                // prevent table cells from being edited. must use dialog to edit.
                return false;
            }
        });

        JScrollPane profileScrollPane = new JScrollPane(profileTable);
        profileScrollPane.setPreferredSize(new Dimension(1000, 200));
        GridBagConstraints c000 = new GridBagConstraints(); c000.gridy = 0; c000.gridwidth = 2; c000.anchor = GridBagConstraints.FIRST_LINE_START;
        GridBagConstraints c001 = new GridBagConstraints(); c001.gridy = 1; c001.gridwidth = 2; c001.anchor = GridBagConstraints.FIRST_LINE_START;
        c001.insets = new Insets(10, 0, 10, 0);
        GridBagConstraints c002 = new GridBagConstraints(); c002.gridy = 2; c002.gridx = 0; c002.anchor = GridBagConstraints.FIRST_LINE_START;
        GridBagConstraints c003 = new GridBagConstraints(); c003.gridy = 2; c003.gridx = 1; c003.anchor = GridBagConstraints.FIRST_LINE_START;
        profilePanel.add(profileLabel, c000);
        profilePanel.add(new JLabel("<html>Add Intercept Rules, intercept response modified body/header accroding request URL. URL must include port number.(e.g., https://github.com:443/xiaoxiaoleo/) </html>"), c001);
        profilePanel.add(profileButtonPanel, c002);
        profilePanel.add(profileScrollPane, c003);

        //
        // put it all together
        //
        List<GridBagConstraints> sectionConstraints = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            GridBagConstraints c = new GridBagConstraints();
            c.gridy = i;
            c.gridx = 0;
            // add padding in all directions
            c.insets = new Insets(10, 10, 10, 10);
            c.anchor = GridBagConstraints.FIRST_LINE_START;
            c.weightx = 1.0;
            sectionConstraints.add(c);
        }

        JPanel outerPanel = new JPanel(new GridBagLayout());
        outerPanel.add(globalSettingsPanel, sectionConstraints.remove(0));
        GridBagConstraints c = sectionConstraints.remove(0);
        c.fill = GridBagConstraints.HORIZONTAL; // have separator span entire width of display
        outerPanel.add(new JSeparator(SwingConstants.HORIZONTAL), c);
        //outerPanel.add(statusPanel, sectionConstraints.remove(0));
        outerPanel.add(profilePanel, sectionConstraints.remove(0));

        // use outerOuterPanel to force components north
        JPanel outerOuterPanel = new JPanel(new BorderLayout());
        outerOuterPanel.add(outerPanel, BorderLayout.PAGE_START);
        outerScrollPane = new JScrollPane(outerOuterPanel);
        outerScrollPane.getVerticalScrollBar().setUnitIncrement(18);

        this.callbacks.customizeUiComponent(outerPanel);

        // profile button handlers
        addReplaceRuleButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                ReplaceRuleEditorDialog dialog = new ReplaceRuleEditorDialog(null, "Add Intercept Rule", true, null);
                callbacks.customizeUiComponent(dialog);
                dialog.setVisible(true);
            }
        });
        editProfileButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                int[] rowIndeces = profileTable.getSelectedRows();
                if (rowIndeces.length == 1) {
                    DefaultTableModel model = (DefaultTableModel) profileTable.getModel();
                    final String name = (String) model.getValueAt(rowIndeces[0], 0);
                    JDialog dialog = new ReplaceRuleEditorDialog(null, "Edit Profile", true, interceptRuleMap.get(name));
                    callbacks.customizeUiComponent(dialog);
                    dialog.setVisible(true);
                }
                else {
                    updateStatus("Select a single rule to edit");
                }
            }
        });
        removeProfileButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                DefaultTableModel model = (DefaultTableModel) profileTable.getModel();
                ArrayList<String> profileNames = new ArrayList<>();
                for (int rowIndex : profileTable.getSelectedRows()) {
                    profileNames.add((String) model.getValueAt(rowIndex, 0));
                }
                for (final String name : profileNames) {
                    deleteProfile(interceptRuleMap.get(name));
                }
            }
        });

        // log level combo box
        class LogLevelComboBoxItem
        {
            final private int logLevel;
            final private String levelName;

            public LogLevelComboBoxItem(final int logLevel)
            {
                this.logLevel = logLevel;
                this.levelName = LogWriter.levelNameFromInt(logLevel);
            }

            @Override
            public String toString()
            {
                return this.levelName;
            }
        }
        this.logLevelComboBox.addItem(new LogLevelComboBoxItem(LogWriter.DEBUG_LEVEL));
        this.logLevelComboBox.addItem(new LogLevelComboBoxItem(LogWriter.INFO_LEVEL));
        this.logLevelComboBox.addItem(new LogLevelComboBoxItem(LogWriter.ERROR_LEVEL));
        this.logLevelComboBox.addItem(new LogLevelComboBoxItem(LogWriter.FATAL_LEVEL));
        this.logLevelComboBox.setSelectedIndex(logger.getLevel());

        this.logLevelComboBox.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                logger.setLevel(((LogLevelComboBoxItem) logLevelComboBox.getSelectedItem()).logLevel);
            }
        });
    }

    public boolean isSigningEnabled()
    {
        return this.signingEnabledCheckBox.isSelected();
    }

    private void setLogLevel(final int level)
    {
        this.logger.setLevel(level);
        // logger is created before UI components are initialized.
        if (this.logLevelComboBox != null) {
            this.logLevelComboBox.setSelectedIndex(logger.getLevel());
        }
    }

    // format a message for display in a dialog. applies reasonable word-wrapping.
    public static String formatMessageHtml(final String msg) {
        return "<html><p style='width: 300px;'>" +
                StringEscapeUtils.escapeHtml4(msg) +
                "</p></html>";
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        burpInstance = this;

        this.helpers = callbacks.getHelpers();
        this.callbacks = callbacks;

        callbacks.setExtensionName(EXTENSION_NAME);
        // 定义输出
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("Author: xiaoxiaoleo");
        stdout.println("Repo: https://github.com/xiaoxiaoleo/Burp-Auto-Do-Intercept");

        this.logger.configure(callbacks.getStdout(), callbacks.getStderr(), LogWriter.DEFAULT_LEVEL);
        final String setting = this.callbacks.loadExtensionSetting(SETTING_LOG_LEVEL);
        if (setting != null) {
            try {
                setLogLevel(Integer.parseInt(setting));
            } catch (NumberFormatException ignored) {
                // use default level
            }
        }

        this.profileUrlPatternMap = new HashMap<>();
        this.interceptRuleMap = new HashMap<>();

        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                buildUiTab();
                callbacks.addSuiteTab(BurpExtender.this);
                callbacks.registerHttpListener(BurpExtender.this);
                logger.info(String.format("Loaded %s %s", EXTENSION_NAME, EXTENSION_VERSION));
            }
        });
    }


    @Override
    public String getTabCaption()
    {
        return DISPLAY_NAME;
    }

    @Override
    public Component getUiComponent()
    {
        return outerScrollPane;
    }


    // display status message in UI
    private void updateStatus(final String status)
    {
        logger.debug("Set Status: " + status);
        this.statusLabel.setText(status);
    }

    private List<String> getSortedProfileNames()
    {
        // sort by name in table
        List<String> profileNames = new ArrayList<>(this.interceptRuleMap.keySet());
        Collections.sort(profileNames);
        return profileNames;
    }

    /*
    call this when profile list changes
    */
    private void updateReplaceRulesUI()
    {
        DefaultTableModel model = (DefaultTableModel) this.profileTable.getModel();
        model.setRowCount(0); // clear table

        for (final String name : getSortedProfileNames()) {
            ReplaceRule profile = this.interceptRuleMap.get(name);
            model.addRow(new Object[]{profile.getName(), profile.getUrlPatternForProfileSelection(), profile.getNewBodyForProfileSelection(), profile.getNewHeaderForProfileSelection(), profile.getNewIsEnableForProfileSelection()});
         }
     }

    /*
    NOTE: this will overwrite an existing profile with the same name
    */
    protected void addReplaceRule(final ReplaceRule profile)
    {
        logger.debug("Add rules :" + profile.getName().toString());
        final ReplaceRule p1 = this.interceptRuleMap.get(profile.getName());
        if (p1 == null) {
            // profile name doesn't exist. make sure there is no keyId conflict with an existing profile
            if (profile.getUrlPatternForProfileSelection() != null) {
                String p2 = this.profileUrlPatternMap.get(profile.getUrlPatternForProfileSelection());
                if (p2 != null) {
                    // keyId conflict. do not add profile
                    updateStatus("ReplaceRules must have a unique UrlPattern: "+profile.getName());
                    throw new IllegalArgumentException(String.format("ReplaceRules must have a unique UrlPattern: %s = %s", profile.getName(), p2));
                }
            }
        }

        this.interceptRuleMap.put(profile.getName(), profile);

        // refresh the keyId map
        this.profileUrlPatternMap.clear();
        for (final ReplaceRule p : this.interceptRuleMap.values()) {
            if (p.getUrlPatternForProfileSelection() != null) {
                this.profileUrlPatternMap.put(p.getUrlPatternForProfileSelection(), p.getName());
            }
        }

        updateReplaceRulesUI();
        if (p1 == null) {
            updateStatus("Added profile: " + profile.getName());
        }
        else {
            updateStatus("Saved profile: " + profile.getName());
        }
    }

    /*
    if newProfile is valid, delete oldProfile and add newProfile.
     */
    protected void updateReplaceRule(final ReplaceRule oldProfile, final ReplaceRule newProfile)
    {
        logger.debug("Updateing rule name: " + newProfile.getName().toString());
        if (oldProfile == null) {
            addReplaceRule(newProfile);
            return;
        }

        // remove any profile with same name
        final ReplaceRule p1 = this.interceptRuleMap.get(oldProfile.getName());
        if (p1 == null) {
            updateStatus("Update profile failed. Old profile doesn't exist.");
            throw new IllegalArgumentException("Update profile failed. Old profile doesn't exist.");
        }

        deleteProfile(oldProfile);
        try {
            addReplaceRule(newProfile);
        } catch (IllegalArgumentException exc) {
            addReplaceRule(oldProfile); // oops. add old profile back
            throw exc;
        }
    }

    private void deleteProfile(ReplaceRule profile)
    {
        if (this.interceptRuleMap.containsKey(profile.getName())) {
            this.interceptRuleMap.remove(profile.getName());
            updateStatus(String.format("Deleted profile '%s'", profile.getName()));
        }
        if (profile.getUrlPatternForProfileSelection() != null) {
            this.profileUrlPatternMap.remove(profile.getUrlPatternForProfileSelection());
        }
        updateReplaceRulesUI();
    }



    public ReplaceRule getInterceptRule(String name)
    {
        ReplaceRule interceptRule = this.interceptRuleMap.get(name);
        return interceptRule;
    }

    public String getInterceptRuleName(final URL url)
    {
        String interceptRule = this.profileUrlPatternMap.get(url.toString());
        return interceptRule;
    }


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {

        if (!isSigningEnabled())
        {
            return;
        }

        URL url = helpers.analyzeRequest(messageInfo).getUrl();

        logger.debug(url.toString());

        String interceptRuleName = getInterceptRuleName(url);
        if( interceptRuleName == null){
            return;
        }

        logger.info("match rule name: " + interceptRuleName);

        ReplaceRule interceptRule = getInterceptRule(interceptRuleName);

        String iUrlPattern = interceptRule.getUrlPattern();
        String newBody = interceptRule.getNewBody();

        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
            if (messageIsRequest == true)
            {
                String headerName = "browser-color:";
                String hColor = "red";
                if (iUrlPattern.equals(url.toString())) {
                    messageInfo.setHighlight(hColor);
                }

             } else {
                    IResponseInfo analyzedResponse = helpers.analyzeResponse(messageInfo.getResponse());
                    logger.info(url.toString());
                    //logger.error(url.toString());
                    //short statusCode = analyzedResponse.getStatusCode();
                    List<String> headers = analyzedResponse.getHeaders();
                    String resp = new String(messageInfo.getResponse());
                    int bodyOffset = analyzedResponse.getBodyOffset();
                    String body = resp.substring(bodyOffset);

                    if (iUrlPattern.equals(url.toString())){
                        try{
                            //String newBody = "{\"errcode\":0,\"data\":{\"assist_num\": 100}}\n";
                            byte[] bodybyte = newBody.getBytes();
                            messageInfo.setResponse(helpers.buildHttpMessage(headers, bodybyte));
                        }catch(Exception e){
                            callbacks.printError(e.getMessage());
                        }
                    }
             }

        }

    }

}

