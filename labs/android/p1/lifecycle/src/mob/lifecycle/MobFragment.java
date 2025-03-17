package mob.lifecycle;

import android.app.Fragment;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

public class MobFragment extends Fragment {
    private static final String TAG = "Frag";

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.d(TAG, "onCreate() called");
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        Log.d(TAG, "onCreateView() called");
        return inflater.inflate(R.layout.fragment_layout, container, false);
    }

    @Override
    public void onStart() {
        super.onStart();
        Log.d(TAG, "fragment onStart() called");
    }

    @Override
    public void onResume() {
        super.onResume();
        Log.d(TAG, "fragment onResume() called");
    }

    @Override
    public void onPause() {
        super.onPause();
        Log.d(TAG, "fragment onPause() called");
    }

    @Override
    public void onStop() {
        super.onStop();
        Log.d(TAG, "fragment onStop() called");
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        Log.d(TAG, "fragment onDestroyView() called");
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.d(TAG, "fragment onDestroy() called");
    }
}
