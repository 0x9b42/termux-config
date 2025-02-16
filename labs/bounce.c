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

void bounce_ball() {
  int rows, cols;
  get_terminal_size(&rows, &cols);

  int x = cols / 2, y = rows / 2;
  int dx = 1, dy = 1;

  while (1) {
    clear_screen();

    for (int i = 0; i < rows; i++) {
      for (int j = 0; j < cols; j++) {
        if (i == y && j == x)
          putchar('O');
        else
          putchar(' ');
      }
      putchar('\n');
    }

    x += dx;
    y += dy;

    if (x <= 0 || x >= cols - 1)
      dx = -dx;
    if (y <= 0 || y >= rows - 1)
      dy = -dy;

    usleep(50000);
  }
}

int main() {
  struct termios oldt, newt;
  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~(ECHO | ICANON);
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);

  bounce_ball();

  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  return 0;
}
