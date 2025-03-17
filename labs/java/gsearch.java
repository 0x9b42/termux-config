//** Google Search **//
import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
public class gsearch {
  public static void main(String[] args) throws IOException {
    String query = "android java code example"; // Search query
    String googleUrl =
        "https://www.google.com/search?q=" + URLEncoder.encode(query, "UTF-8");
    Document doc = Jsoup.connect(googleUrl)
                       .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
                                  "AppleWebKit/537.36 (KHTML, like Gecko) " +
                                  "Chrome/58.0.3029.110 Safari/537.36")
                       .get();
    Elements searchResults = doc.select("div.g");
    List<String> urls = new ArrayList<>();
    for (Element result : searchResults) {
      Element link = result.select("a").first();
      String url = link.attr("href");
      if (url.startsWith("/url?q=")) {
        url = url.substring(7, url.indexOf("&"));
        urls.add(url);
      }
    }
    for (String url : urls) {
      System.out.println(url); // Print the URL to console
    }
  }
}
