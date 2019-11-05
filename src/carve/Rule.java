/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package carve;

import burp.Highlighter;
import burp.ICookie;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 *
 * @author asuarez
 */
// Serializable class. This should be replaced with JSON serialization.
public class Rule implements Serializable
{

    private static int count = 0;

    private String name;
    private String action;
    private final int id;
    private Boolean active;
    private Boolean case_sensitive;
    private String color;
    private String section;
    private String target;
    private String regex;
    private String match_type;
    private Boolean is_negative_search;
    private Boolean in_scope_only;

    public Rule()
    {
        // Increment unique id
        count++;

        id = count;
        in_scope_only = false;
        case_sensitive = false;
        name = "Rule " + count;
        active = false;

        color = Highlighter.arrayColorStrings[id % 8];

        section = "Any";
        target = "Request";
        match_type = "Substring";
        is_negative_search = false;
        action = "Both";
        regex = "";
    }

    /**
     *
     * @return Returns the comment to display on the proxy tab for this rule
     * when matched
     */
    public String getComment()
    {
        if (is_negative_search)
        {
            return String.format("[%s]: %s not found on %s/%s", name, regex, target.toString(), section.toString());

        } else
        {
            return String.format("[%s]: %s found on %s/%s", name, regex, target.toString(), section.toString());
        }
    }

    public Boolean getCaseSensitivity()
    {
        return case_sensitive;
    }

    /**
     *
     * Determines whether the current request is a match on this rule
     *
     * @param element the current request
     * @param type current request type (request/response)
     * @return
     */
    public Boolean matchesCondition(IHttpRequestResponse element, String type)
    {
        Boolean matches = false;
        String target_content = "";

        if (!isActive())
        {
            return false;
        }

        if (getRegex().equals(""))
        {
            return true;
        }

        // Matching against "Request" or both
        if (type.equals("Request") && (target.equals("Request") || target.equals("Both")))
        {
            target_content = getTargetContentFromRequest(element);
        } // Matching against "Response" or both
        else if (type.equals("Response") && (target.equals("Response") || target.equals("Both")))
        {
            target_content = getTargetContentFromResponse(element);
        }

        // ToDo: why?
        if (target_content.equals(""))
        {
            return false;
        }

        // If regex mode, compile and determine match
        if (getMatchType().equals("Regex"))
        {
            Pattern pattern = Pattern.compile(getRegex());
            Matcher matcher;

            matcher = pattern.matcher(target_content);
            matches = matcher.matches();
        } else if (target_content.contains(getRegex()))
        {
            matches = true;
        }

        // matches XOR negative_flag gives us negative-matching functionality
        return matches ^ isNegativeSearch();
    }

    /**
     * Extracts the rule matching target from the current request
     *
     * @param element the current request
     * @return
     */
    public String getTargetContentFromRequest(IHttpRequestResponse element)
    {

        String target_content = "";
        IRequestInfo request;

        // ToDo: is this correct??
        // shouldn't this be just a try catch for the getRequest one, returning "" on fail?
        try
        {
            request = Highlighter.my_helpers.analyzeRequest(element);
        } catch (java.lang.NullPointerException e)
        {
            request = Highlighter.my_helpers.analyzeRequest(element.getRequest());
        }

        if (in_scope_only && !Highlighter.my_callbacks.isInScope(request.getUrl()))
        {
            Highlighter.printf("URL NOT in scope: %s, shouldn't be highlighted", request.getUrl().toString());
            return "";
        }

        switch (getMatchSection())
        {
            case "Method":
                target_content = request.getMethod();
                break;

            case "URL":
                target_content = request.getUrl().toString();
                break;

            case "Header":
                target_content = request.getHeaders().toString();
                break;

            case "Body":
                //IRequestInfo objects don't directly return the request body
                //instead, they return the body offset in the request
                int body_offset = request.getBodyOffset();

                byte body[] = Arrays.copyOfRange(element.getRequest(), body_offset, element.getRequest().length);
                target_content = new String(body);

                break;
            case "Any":
                target_content = new String(element.getRequest());
                break;
        }

        return target_content;
    }

    /**
     * Extracts the rule matching target from the current response
     *
     * @param element the current response
     * @return
     */
    public String getTargetContentFromResponse(IHttpRequestResponse element)
    {

        String target_content = "";
        IResponseInfo response;

        try
        {
            response = Highlighter.my_helpers.analyzeResponse(element.getResponse());
        } catch (java.lang.NullPointerException e)
        {
            return "";
        }

        switch (getMatchSection())
        {
            case "Cookies":
                List<ICookie> cookie_list = response.getCookies();

                for (ICookie cookie : cookie_list)
                {
                    target_content = target_content + cookie.getName() + ": " + cookie.getValue() + "\n";
                }

                break;

            case "Header":
                target_content = response.getHeaders().toString();
                break;

            case "Body":
                int body_offset = response.getBodyOffset();

                byte body[] = Arrays.copyOfRange(element.getResponse(), body_offset, element.getResponse().length);
                target_content = new String(body);

                break;

            case "Mime":
                target_content = response.getStatedMimeType();
                break;

            case "StatusCode":
                target_content = Short.toString(response.getStatusCode());
                break;

            case "Any":
                target_content = new String(element.getResponse());
                break;
        }

        return target_content;
    }

    public void setInScope(Boolean value)
    {
        in_scope_only = value;
    }

    public Boolean getInScope()
    {
        return in_scope_only;
    }

    public String getAction()
    {
        return action;
    }

    public Boolean isActive()
    {
        return active;
    }

    public Boolean isNegativeSearch()
    {
        return is_negative_search;
    }

    public String getName()
    {
        return name;
    }

    public String getMatchType()
    {
        return match_type;
    }

    public int getID()
    {
        return id;
    }

    public String getColor()
    {
        return color;
    }

    public String getRegex()
    {
        return regex;
    }

    public String getMatchSection()
    {
        return section.toString();
    }

    public String getMatchTarget()
    {
        return target.toString();
    }

    public void enable()
    {
        active = true;
    }

    public void disable()
    {
        active = false;
    }

    public void setColor(String pColor)
    {
        color = pColor;
    }

    public void setMatchType(String pType)
    {
        if (pType.equals("Regex"))
        {
            match_type = "Regex";
        } else
        {
            match_type = "Substring";
        }
    }

    public void setRegex(String pRegex)
    {
        regex = pRegex;
    }

    public void setTarget(String pTarget)
    {
        target = pTarget;
    }

    public void setSection(String pSection)
    {
        section = pSection;
    }

    public void setNegative(Boolean pNegative)
    {
        is_negative_search = pNegative;
    }

    public void setName(String pName)
    {
        name = pName;
    }

    public void setAction(String pAction)
    {
        action = pAction;
    }

    public Boolean checkRegex()
    {
        try
        {
            Pattern.compile(regex);
        } catch (PatternSyntaxException exception)
        {
            return false;
        }
        return true;
    }

    public Boolean match(IHttpRequestResponse incoming)
    {
        //placeholder
        return true;
    }

}
