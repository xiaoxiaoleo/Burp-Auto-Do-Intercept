package burp;

import java.util.regex.Pattern;

/*
Class represents a credential set for AWS services. Provides functionality
to import credentials from environment vars or a credential file.
*/
public class ReplaceRule implements Cloneable
{
    public static final int DEFAULT_STATIC_PRIORITY = 100;

    private static final transient LogWriter logger = LogWriter.getLogger();

    private String name;
    // UrlPattern is used to uniquely identify this profile for signing
    private String UrlPattern;
    private String NewBody;
    private String NewHeader;
    private String isEnable;

    //
    public static final Pattern profileNamePattern = Pattern.compile("^[\\w+=,.@-]{1,64}$");
    //public static final Pattern UrlPatternPattern = Pattern.compile("<\\b(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]>");
    public static final Pattern UrlPatternPattern = Pattern.compile("<\\b(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]>");

    public String getName() { return this.name; }


    // NOTE that this value is used for matching incoming requests only and DOES NOT represent the UrlPattern
    // used to sign the request
    public String getUrlPattern() { return this.UrlPattern; }
    public String getNewBody() { return this.NewBody; }
    public String getNewHeader() { return this.NewHeader; }
    public String getIsEnable() { return this.isEnable; }
    /*
    get the signature UrlPattern that should be used for selecting this profile
     */
    public String getUrlPatternForProfileSelection()
    {
        if (getUrlPattern() != null) {
            return getUrlPattern();
        }
        return null;
    }

    public String getNewBodyForProfileSelection()
    {
        if (getNewBody() != null) {
            return getNewBody();
        }
        return null;
    }

    public String getNewHeaderForProfileSelection()
    {
        if (getNewHeader() != null) {
            return getNewHeader();
        }
        return null;
    }

    public String getNewIsEnableForProfileSelection()
    {
        if (getIsEnable() != null) {
            return getIsEnable();
        }
        return null;
    }
    private void setName(final String name) {
        if (profileNamePattern.matcher(name).matches())
            this.name = name;
        else
            throw new IllegalArgumentException("Profile name must match pattern "+profileNamePattern.pattern());
    }

    private void setUrlPattern(final String UrlPattern) {
        //if (UrlPatternPattern.matcher(UrlPattern).matches())
            this.UrlPattern = UrlPattern;/*
        else
            throw new IllegalArgumentException("Profile UrlPattern must match pattern " + UrlPatternPattern.pattern());*/
    }

    private void setNewBody(final String NewBody) {
        this.NewBody = NewBody;
    }
    private void setNewHeader(final String NewHeader) {
        this.NewHeader = NewHeader;
    }
    public static class Builder {
        private ReplaceRule profile;
        public Builder(final String name) {
            this.profile = new ReplaceRule(name);
        }
        public Builder withUrlPatternNewBody(final String UrlPattern, final String NewBody, final String NewHeader) {
            this.profile.setUrlPattern(UrlPattern);
            this.profile.setNewBody(NewBody);
            this.profile.setNewHeader(NewHeader);
            return this;
        }
        public ReplaceRule build() {
            return this.profile;
        }
    }

    public ReplaceRule clone() {
        ReplaceRule.Builder builder = new ReplaceRule.Builder(this.name);
        return builder.build();
    }


    private ReplaceRule(final String name)
    {
        setName(name);
        this.UrlPattern = null;
        this.NewBody = null;
    }


    @Override
    public String toString() {
        return String.format("UrlPattern = %s \nNewBody=%s\n", UrlPattern, NewBody);
    }
}
