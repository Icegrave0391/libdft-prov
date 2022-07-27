#ifndef __TAINTMAP_H__
#define __TAINTMAP_H__

#include "debug.h"
#include "tag_traits.h"
#include "tagmap.h"
#include<iostream>
#include<map>
#include<set>

typedef std::map<tag_t, std::set<std::string>> TAINT_MAP;

std::string set_to_string(std::set<std::string>& aset);
void update_taintmap(TAINT_MAP& amap, tag_t tag, std::string source_str);
const std::set<std::string> lookup_taintmap(TAINT_MAP& amap, tag_t tag);

#endif /* __TAGMAP_H__ */