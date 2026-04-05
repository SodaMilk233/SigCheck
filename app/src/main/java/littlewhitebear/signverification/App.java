package littlewhitebear.signverification;

import android.app.Application;

public class App extends Application {

    static {
        char[] libName = {'S', 'i', 'g', 'n', 'V', 'e', 'r', 'i', 'f', 'y'};
        System.loadLibrary(new String(libName));
    }
}