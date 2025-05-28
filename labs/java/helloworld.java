package mob;

public class helloworld {

  public String text;

  public static void main(String s[]) {
    for (int i = 0; i < 10; i++)
      System.out.println("hello world!");

    Text t = new Text();
    t.setText("baka");
    t.print();
    t.clear();
    t.print();
  }
}

class Text {
  private String text;

  void setText(String t) {
    text = t;
  }

  void clear() {
    text = "(cleared)";
  }

  void print() {
    System.out.println(text);
  }
}
