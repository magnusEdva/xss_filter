import static java.nio.file.StandardCopyOption.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.*;
import java.util.*;

public class CopyProject {

    public static final String HOME_DIR = "";
    public static final String SRC_DIR = HOME_DIR + "/gecko-dev/";
    public static final String DST_DIR = HOME_DIR + "/xss_filter/";
    public static final String DOM_DIR = "dom/";
    public static final String BASE_DIR = DOM_DIR + "base/";
    public static final String JSURL_DIR = DOM_DIR + "jsurl/";
    public static final String SCRIPT_DIR = DOM_DIR + "script/";
    public static final String SECURITY_DIR = DOM_DIR + "security/";
    public static final String EVENTS_DIR = DOM_DIR + "events/";

    public static void main(String[] args) {
        CopyProject copy = new CopyProject();
        List<FilesToCopy> files = copy.setUpList();
        File homedir = new File(System.getProperty("user.home"));
        for (FilesToCopy file : files) {
            try {
                if (file.isCppFile) {

                    Files.copy(Paths.get(homedir.getAbsolutePath() + SRC_DIR + file.dir + file.name + ".cpp"),
                            Paths.get(homedir.getAbsolutePath() + DST_DIR + file.dir + file.name + ".cpp"),
                            REPLACE_EXISTING);
                    Files.copy(Paths.get(homedir.getAbsolutePath() + SRC_DIR + file.dir + file.name + ".h"),
                            Paths.get(homedir.getAbsolutePath() + DST_DIR + file.dir + file.name + ".h"),
                            REPLACE_EXISTING);
                } else {
                    Files.copy(Paths.get(homedir.getAbsolutePath() + SRC_DIR + file.dir + file.name),
                            Paths.get(homedir.getAbsolutePath() + DST_DIR + file.dir + file.name), REPLACE_EXISTING);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public enum FilesToCopy {
        Document(BASE_DIR, "Document", true), ScriptLoader(SCRIPT_DIR, "ScriptLoader", true),
        XSSFilter(SECURITY_DIR, "XSSFilter", true), EventListenerManager(EVENTS_DIR, "EventListenerManager", true),
        nsJSProtoclHandler(JSURL_DIR, "nsJSProtocolHandler", true);

        FilesToCopy(String dir, String name, Boolean isCppFile) {
            this.dir = dir;
            this.name = name;
            this.isCppFile = isCppFile;
        }

        public final String dir;
        public final String name;
        public final Boolean isCppFile; // or has headerfile
    }

    public List<FilesToCopy> setUpList() {
        List fileList = new ArrayList<FilesToCopy>();
        fileList.add(FilesToCopy.Document);
        fileList.add(FilesToCopy.ScriptLoader);
        fileList.add(FilesToCopy.XSSFilter);
        fileList.add(FilesToCopy.EventListenerManager);
        fileList.add(FilesToCopy.nsJSProtoclHandler);
        return fileList;
    }
}