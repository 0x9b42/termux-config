package mob.demoapp;


import android.app.Activity;
import android.os.Bundle;
import android.widget.Toast;


public class Main extends Activity {
    static {
        System.loadLibrary("test");
    }

    @Override
    protected void onCreate(Bundle bundel) {
        super.onCreate(bundel);
        setContentView(R.layout.layarutama);

        Toast.makeText(
            this, sayHello(), 1
        ).show();

    }

    public native String sayHello();
}

