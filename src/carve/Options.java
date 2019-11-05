/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package carve;

import burp.IBurpExtenderCallbacks;
import burp.Highlighter;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 *
 * @author asuarez
 */
public class Options
{

    public static Boolean persist;
    public static Boolean debug = true;

    public static Path save_dir;
    private static final IBurpExtenderCallbacks cb = Highlighter.my_callbacks;

    private static final String SAVE_DIR_KEY = "burpHighlighter_saveDir";
    private static final String PERSITENCE_ENABLED_KEY = "burpHighlighter_persistenceEnabled";
    private static final String DEBUG_KEY = "burpHighlighter_debugEnabled";

    public Options()
    {

        Path default_dir = Paths.get(System.getProperty("user.home"), ".local", "burp-highlighter");
        String val = null;
        Highlighter.printf("\nLoading options...\n");

        try
        {
            val = Highlighter.getCallbacks().loadExtensionSetting(PERSITENCE_ENABLED_KEY);
            if (val.equals("True"))
            {
                persist = true;
            } else
            {
                persist = false;
            }
        } catch (NullPointerException e)
        {
            persist = true;

        }

        try
        {
            val = Highlighter.getCallbacks().loadExtensionSetting(SAVE_DIR_KEY);
            save_dir = Paths.get(val);
        } catch (NullPointerException e)
        {
            save_dir = default_dir;

        }

        try
        {
            val = Highlighter.getCallbacks().loadExtensionSetting(DEBUG_KEY);
            if (val.equals("True"))
            {
                debug = true;
            } else
            {
                debug = false;
            }
        } catch (NullPointerException e)
        {
            debug = true;

        }
    }

    public static void setSaveDir(String new_dir)
    {
        save_dir = Paths.get(new_dir);
        Highlighter.getCallbacks().saveExtensionSetting(SAVE_DIR_KEY, new_dir);
        Highlighter.printf("\nNew save dir: %s ", save_dir);
    }

    public static void setDebug(String new_val)
    {
        if (new_val.equals("True"))
        {
            Highlighter.getCallbacks().saveExtensionSetting(DEBUG_KEY, "True");
        } else
        {
            Highlighter.getCallbacks().saveExtensionSetting(DEBUG_KEY, "False");
        }
    }

    public static void setPersist(String new_val)
    {
        if (new_val.equals("True"))
        {
            Highlighter.getCallbacks().saveExtensionSetting(PERSITENCE_ENABLED_KEY, "True");
        } else
        {
            Highlighter.getCallbacks().saveExtensionSetting(PERSITENCE_ENABLED_KEY, "False");
        }
    }
}
