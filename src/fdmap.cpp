#include "fdmap.h"
#include "branch_pred.h"
#include "debug.h"

#include <iostream>
#include <set>
#include <unistd.h>


std::map <int, std::string> init_fdmap() {
  std::map<int, std::string> m;
  m[0] = "stdin";
  m[1] = "stdout";
  m[2] = "stderr";
  return m;
}
std::map <int, std::string> fdmap = init_fdmap();

void update_fdmap(std::map<int, std::string>& amap, int fd, std::string str_content) {
    auto it = amap.find(fd);
    if (it != amap.end()) {
        it->second = str_content;
    } else {
        amap.insert(std::make_pair(fd, str_content));
    }
    LOGD("[fdmap] update %d -> %s\n", fd, str_content.c_str());
    return;
}

const std::string lookup_fdmap(std::map<int, std::string>& amap, int fd) {
    auto it = amap.find(fd);
    if (it != amap.end()) {
        return it->second;
    }
    else {
        return "none";
    }
}