#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define WIDTH 80
#define HEIGHT 24
#define SCALE 10
#define ROT_SPEED 0.1

void clear_screen() { printf("\033[H\033[J"); }

void render_cube(float angleX, float angleY, float angleZ) {
  char buffer[WIDTH * HEIGHT];
  memset(buffer, ' ', sizeof(buffer));

  float vertices[8][3] = {{-1, -1, -1}, {1, -1, -1}, {1, 1, -1}, {-1, 1, -1},
                          {-1, -1, 1},  {1, -1, 1},  {1, 1, 1},  {-1, 1, 1}};

  int projected[8][2];
  for (int i = 0; i < 8; i++) {
    float x = vertices[i][0], y = vertices[i][1], z = vertices[i][2];

    float tempX = x * cos(angleY) - z * sin(angleY);
    float tempZ = x * sin(angleY) + z * cos(angleY);
    x = tempX;
    z = tempZ;

    float tempY = y * cos(angleX) - z * sin(angleX);
    z = y * sin(angleX) + z * cos(angleX);
    y = tempY;

    int screenX = (int)(WIDTH / 2 + x * SCALE);
    int screenY = (int)(HEIGHT / 2 - y * SCALE);
    projected[i][0] = screenX;
    projected[i][1] = screenY;
  }

  int edges[12][2] = {{0, 1}, {1, 2}, {2, 3}, {3, 0}, {4, 5}, {5, 6},
                      {6, 7}, {7, 4}, {0, 4}, {1, 5}, {2, 6}, {3, 7}};

  for (int i = 0; i < 12; i++) {
    int x1 = projected[edges[i][0]][0], y1 = projected[edges[i][0]][1];
    int x2 = projected[edges[i][1]][0], y2 = projected[edges[i][1]][1];

    int dx = abs(x2 - x1), dy = abs(y2 - y1);
    int sx = x1 < x2 ? 1 : -1, sy = y1 < y2 ? 1 : -1;
    int err = dx - dy;

    while (x1 != x2 || y1 != y2) {
      if (x1 >= 0 && x1 < WIDTH && y1 >= 0 && y1 < HEIGHT) {
        buffer[y1 * WIDTH + x1] = '#';
      }
      int e2 = 2 * err;
      if (e2 > -dy) {
        err -= dy;
        x1 += sx;
      }
      if (e2 < dx) {
        err += dx;
        y1 += sy;
      }
    }
  }

  clear_screen();
  for (int i = 0; i < HEIGHT; i++) {
    for (int j = 0; j < WIDTH; j++) {
      putchar(buffer[i * WIDTH + j]);
    }
    putchar('\n');
  }
}

int main() {
  float angleX = 0, angleY = 0, angleZ = 0;
  while (1) {
    render_cube(angleX, angleY, angleZ);
    angleX += ROT_SPEED;
    angleY += ROT_SPEED;
    angleZ += ROT_SPEED;
    usleep(50000);
  }
  return 0;
}
