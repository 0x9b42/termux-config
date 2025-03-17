#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

void get_terminal_size(int *rows, int *cols) {
  struct winsize w;
  ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
  *rows = w.ws_row;
  *cols = w.ws_col;
}

void clear_screen() { printf("\033[H\033[J"); }

void plot_sine_wave() {
  int rows, cols;
  get_terminal_size(&rows, &cols);

  while (1) {
    clear_screen();
    for (int i = 0; i < rows; i++) {
      for (int j = 0; j < cols; j++) {
        double x = (double)j / cols * 4.0 * M_PI;
        int y = (int)((sin(x) + 1) * (rows / 2));
        if (y == i)
          putchar('*');
        else
          putchar(' ');
      }
      putchar('\n');
    }
    usleep(100000);
  }
}

int main() {
  struct termios oldt, newt;
  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~(ECHO | ICANON);
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);

  plot_sine_wave();

  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  return 0;
}
