import android.widget.Toast;
import android.content.Context;

public class toast {
    public static void show(Context c, String msg) {
        Toast.makeText(
            c, msg, Toast.LENGTH_LONG
        ).show();
    }
}
