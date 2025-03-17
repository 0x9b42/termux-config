package mob.lifecycle;

import android.app.Activity;
import android.app.Fragment;
import android.app.FragmentManager;
import android.app.FragmentTransaction;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

public class Main extends Activity {
  private static final String TAG = "Lifecycle";

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.main);

    Button addFragmentButton = findViewById(R.id.addFragmentButton);
    addFragmentButton
      .setOnClickListener(new View.OnClickListener() {
      @Override
      public void onClick(View v) {
        addFragment();
      }
    });

    Log.d(TAG, "onCreate() called");
    t("onCreate called!");
  }

  private void addFragment() {
    t("added fragment");
    FragmentManager fragmentManager = getFragmentManager();
    FragmentTransaction transaction = fragmentManager.beginTransaction();
    transaction.replace(R.id.fragmentContainer, new MobFragment());
    transaction.addToBackStack(null); // Allow back navigation
    transaction.commit();
  }

  public void t(String msg) {
    Toast.makeText(this, msg, 0).show();
  }
}
