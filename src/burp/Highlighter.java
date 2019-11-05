/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.io.PrintWriter;
import carve.*;
import java.awt.Color;
import java.awt.Component;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

/**
 *
 * @author asuarez
 */
public class Highlighter implements IBurpExtender, IProxyListener, ITab
{

    public static IBurpExtenderCallbacks my_callbacks;
    public static IExtensionHelpers my_helpers;

    private static PrintWriter my_stdout;
    private static PrintWriter my_stderr;

    public static Options my_options;

    private static carve.HighlightGUI my_gui;

    private static final String extension_name = "Highlight";

    public static List<Rule> my_rules = new ArrayList<Rule>();

    public static String[] arrayActions =
    {
        "Highlight", "Comment", "Both"
    };

    public static String[] arrayTargets =
    {
        "Request", "Response", "Both"
    };

    public static String[] arrayColorStrings =
    {
        "Red", "Blue", "Pink", "Green", "Magenta", "Cyan", "Gray", "Yellow", "Clear"
    };

    public static Color[] arrayColorObjs =
    {
        Color.RED, Color.BLUE, Color.PINK, Color.GREEN, Color.MAGENTA, Color.CYAN, Color.GRAY, Color.YELLOW, Color.BLACK
    };
    private static boolean True;

    private static JFileChooser fc = new JFileChooser();

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {

        Highlighter.my_callbacks = callbacks;
        Highlighter.my_helpers = my_callbacks.getHelpers();

        my_callbacks.setExtensionName(extension_name);
        my_callbacks.registerProxyListener(this);

        my_gui = new HighlightGUI();
        my_callbacks.addSuiteTab(this);

        initialize();
    }

    private void initialize()
    {
        // get stderr and stdout for debug output
        my_stdout = new PrintWriter(my_callbacks.getStdout(), true);
        my_stderr = new PrintWriter(my_callbacks.getStderr(), true);

        // populate the panel with a initial rule
        createRule();
    }

    @Override
    public String getTabCaption()
    {
        return extension_name;
    }

    @Override
    public Component getUiComponent()
    {
        return my_gui;
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message)
    {
        IHttpRequestResponse element = message.getMessageInfo();
        processElement(messageIsRequest, element);
    }

    /**
     * Loops through all the elements in the proxy tab, processing both request and responses
     */
    public static void scanHistory()
    {
        for (IHttpRequestResponse proxy_element : my_callbacks.getProxyHistory())
        {
            processElement(true, proxy_element);
            processElement(false, proxy_element);
        }
    }

    /**
     * Once a a match has been confirmed, this function performs the specified action on the ReqRes element
     * @param element the current iHTTP element
     * @param color the specified color
     * @param rule the rule containing the desired action
     */
    private static void performAction(IHttpRequestResponse element, String color, Rule rule)
    {
        switch (rule.getAction())
        {
            case "Highlight":
                if (color.equals("clear"))
                {
                    element.setHighlight(null);
                } else
                {
                    element.setHighlight(rule.getColor().toLowerCase());
                }
                break;

            case "Comment":
                if (color.equals("clear"))
                {
                    element.setComment("");
                } else
                {
                    element.setComment(rule.getComment());
                }

                break;

            default:
                if (color.equals("clear"))
                {
                    element.setComment("");
                    element.setHighlight(null);

                } else
                {
                    element.setComment(rule.getComment());
                    element.setHighlight(rule.getColor().toLowerCase());
                }
        }
    }

    /**
     * Loops through the current rule list trying to find a match against the specified iHTTP object
     * @param messageIsRequest is the message a request (true) or a response (false)?
     * @param element the element being processed
     */
    public static void processElement(boolean messageIsRequest, IHttpRequestResponse element)
    {
        for (Rule rule : my_rules)
        {
            String color = rule.getColor().toLowerCase();

            if (messageIsRequest)
            {
                if (rule.matchesCondition(element, "Request"))
                {
                    performAction(element, color, rule);
                }
            } else
            {
                if (rule.matchesCondition(element, "Response"))
                {
                    performAction(element, color, rule);
                }
            }
        }
    }

    /**
     * Creates a new rule and notifies the GUI object to do the same.
     */
    public static void createRule()
    {
        Rule newRule = new Rule();
        my_rules.add(newRule);
        my_gui.addRule(newRule);
    }

    /**
     * Removes a rule specified by its unique identifier
     * @param rule_id target rule unique identifier
     */
    public static void removeRule(int rule_id)
    {
        Iterator itr = my_rules.iterator();

        while (itr.hasNext())
        {
            Rule target = (Rule) itr.next();
            if (target.getID() == rule_id)
            {
                itr.remove();
            }
        }
    }

    // ToDo: a single check for debug flag should be added here, then search and remove any other if on print
    public static void printf(String s, Object... objs)
    {
        if (my_stdout != null)
        {
            my_stdout.printf(s, objs);
        } else
        {
            System.out.printf(s, objs);
        }
    }

    //(de)serialization needs a rework. this is just a naive proof of concept.
    //this eventually will be json-based. soon.
    public static void importRules()
    {
        int dialogButton = JOptionPane.YES_NO_OPTION;
        int dialogResult = JOptionPane.showConfirmDialog(null, "This action will delete all current rules.\nContinue?", "Warning", dialogButton);

        if (dialogResult == JOptionPane.YES_OPTION)
        {
            // Delete all current rules
            my_gui.clearRules();

            // Choose import file
            fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
            fc.setMultiSelectionEnabled(false);
            fc.showOpenDialog(my_gui);

            File input_file = fc.getSelectedFile();

            try
            {
                FileInputStream fileIn = new FileInputStream(input_file);
                ObjectInputStream in = new ObjectInputStream(fileIn);

                my_rules = (ArrayList<Rule>) in.readObject();
                in.close();
                fileIn.close();
            } catch (IOException i)
            {
                i.printStackTrace();
            } catch (ClassNotFoundException c)
            {
                c.printStackTrace();
                return;
            }

            // Add imported rules to GUI
            for (Rule rule : my_rules)
            {
                my_gui.addRule(rule);
            }
        }

    }

    public static void exportRules()
    {
        fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
        fc.setMultiSelectionEnabled(false);
        fc.showSaveDialog(my_gui);

        File output_file = fc.getSelectedFile();

        try
        {
            FileOutputStream fileOut = new FileOutputStream(output_file);
            ObjectOutputStream out = new ObjectOutputStream(fileOut);
            out.writeObject(my_rules);
            out.close();
            fileOut.close();
        } catch (IOException i)
        {
            i.printStackTrace();
        }
    }

    public static void debugf(String s, Object... objs)
    {
        // if (!PluginOptions.getOpts().isDebug())
        // ToDo: Implement debug flag in plugin options
        printf("[DEBUG] " + s, objs);
    }

    public static void printDebugInfo()
    {
        debugf("ArrayList size: %d\n", Highlighter.my_rules.size());

        debugf("Current rule settings\n");

        for (Rule rule : my_rules)
        {
            debugf("<%d> (%s): [Active: %s] --action-- %s \n\tNegative: %s \n\tMatchType: %s\n\tTerm: %s\n\tColor: %s\n\tTarget: %s\n\tSection: %s\n\tIn scope only: %s\n",
                    rule.getID(),
                    rule.getName(),
                    rule.isActive(),
                    rule.getAction(),
                    rule.isNegativeSearch(),
                    rule.getMatchType(),
                    rule.getRegex(),
                    rule.getColor(),
                    rule.getMatchTarget(),
                    rule.getMatchSection(),
                    rule.getInScope()
            );
        }
        debugf("---------------------");
        my_gui.dbgRules();

    }

    public static IBurpExtenderCallbacks getCallbacks()
    {
        return my_callbacks;
    }

}
