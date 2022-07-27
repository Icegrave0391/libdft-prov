#include "taintmap.h"

TAINT_MAP taint_map;

std::string set_to_string(std::set<std::string>& aset) {
    std::string s = "{";
    for (auto const& e: aset) {
        s += e;
        s += ",";
    }
    s.pop_back();
    s += "}";
    return s;
}

void update_taintmap(TAINT_MAP& amap, tag_t tag, std::string source_str) {
    auto it = amap.find(tag);
    if (it != amap.end()) {
        std::set<std::string> source_set = it->second;
        source_set.insert(source_str);
        LOGD("[taintmap] update %s -> %s\n", tag_sprint<tag_t>(tag).c_str(), set_to_string(source_set).c_str());
    } else {
        std::set<std::string> source_set;
        source_set.insert(source_str);
        amap.insert(std::make_pair(tag, source_set));
        LOGD("[taintmap] update %s -> %s\n", tag_sprint<tag_t>(tag).c_str(), set_to_string(source_set).c_str());
    }
    return;
}

const std::set<std::string> lookup_taintmap(TAINT_MAP& amap, tag_t tag) {
    auto it = amap.find(tag);
    if (it != amap.end()) {
        return it->second;
    }
    std::set<std::string> tmp;
    tmp.insert("none");
    return tmp;
}