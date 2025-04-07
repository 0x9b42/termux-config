package mob.tesaja;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;
import android.view.Gravity;
import android.app.AlertDialog;

public class MainActivity extends Activity {
  @Override
  protected void onCreate(Bundle bundel) {
    super.onCreate(bundel);

    TextView helo = new TextView(this);
    helo.setText("hola mundo!");
    helo.setGravity(Gravity.CENTER);
    helo.setTextSize(24);

    setContentView(helo);

    Toast.makeText(this, "heyhey", 1).show();


    new AlertDialog.Builder(this)
      .setTitle("coba")
      .setMessage("ohayou gozaimasu")
      .show();
  }
}
