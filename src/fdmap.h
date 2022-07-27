#ifndef __FDMAP_H__
#define __FDMAP_H__
#include <iostream>
#include <map>

void update_fdmap(std::map<int, std::string>& amap, int fd, std::string str_content);
const std::string lookup_fdmap(std::map<int, std::string>& amap, int fd);

#endif
