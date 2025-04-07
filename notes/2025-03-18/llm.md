[14:18] To set width and height of a TextView (or any View) in pure Java, use LayoutParams. The approach depends on the parent layout.


---

1. Setting Width & Height for TextView in Java

import android.app.Activity;
import android.os.Bundle;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Create a TextView
        TextView textView = new TextView(this);
        textView.setText(Hello, Android!);

        // Create LayoutParams with custom width & height
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                300,  // Width in pixels
                150   // Height in pixels
        );

        // Set margins (optional)
        params.setMargins(50, 20, 50, 20);

        // Apply LayoutParams to the TextView
        textView.setLayoutParams(params);

        // Create a LinearLayout and add the TextView
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.addView(textView);

        // Set the layout as the content view
        setContentView(layout);
    }
}


---

2. Using Constants for Width & Height

Instead of fixed pixel values, you can use:
✅ ViewGroup.LayoutParams.MATCH_PARENT → Fill parent width/height
✅ ViewGroup.LayoutParams.WRAP_CONTENT → Adjust size based on content

Example:

LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,  // Full width
        ViewGroup.LayoutParams.WRAP_CONTENT   // Height based on text
);


---

3. Converting dp to px (For Responsive UI)

Pixels (px) are not recommended for dynamic layouts. Convert dp to pixels instead:

int widthInDp = 150;  // Desired width in dp
int heightInDp = 50;  // Desired height in dp

// Convert to pixels
int widthInPx = (int) (widthInDp * getResources().getDisplayMetrics().density);
int heightInPx = (int) (heightInDp * getResources().getDisplayMetrics().density);

// Apply to LayoutParams
LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(widthInPx, heightInPx);


---

4. Different Parent Layouts Require Different LayoutParams

Use the correct LayoutParams for your layout:

For RelativeLayout:

RelativeLayout.LayoutParams params = new RelativeLayout.LayoutParams(300, 150);

For FrameLayout:

FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(300, 150);



---

TL;DR

✅ Use LayoutParams(width, height).
✅ Use MATCH_PARENT / WRAP_CONTENT for flexibility.
✅ Convert dp to px for responsive design.

Let me know if your TextView is still misbehaving!



