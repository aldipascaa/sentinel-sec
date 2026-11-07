#include <algorithm>

#include "sentinel/portrange.hpp"

namespace sentinel {
namespace {

struct Svc {
    std::uint16_t port;
    const char* name;
};

constexpr Svc kServices[] = {
    {20, "ftp-data"},   {21, "ftp"},          {22, "ssh"},         {23, "telnet"},
    {25, "smtp"},       {53, "dns"},          {67, "dhcp"},        {80, "http"},
    {88, "kerberos"},   {110, "pop3"},        {111, "rpcbind"},    {123, "ntp"},
    {135, "msrpc"},     {137, "netbios-ns"},  {139, "netbios-ssn"}, {143, "imap"},
    {389, "ldap"},      {443, "https"},       {445, "microsoft-ds"}, {465, "smtps"},
    {514, "syslog"},    {587, "submission"},  {636, "ldaps"},      {993, "imaps"},
    {995, "pop3s"},     {1433, "mssql"},      {1521, "oracle"},    {2049, "nfs"},
    {3000, "http-dev"}, {3306, "mysql"},      {3389, "rdp"},       {5000, "http-dev"},
    {5432, "postgresql"}, {5900, "vnc"},      {5985, "winrm"},     {5986, "winrm-ssl"},
    {6379, "redis"},    {8000, "http-alt"},   {8080, "http-proxy"}, {8443, "https-alt"},
    {8787, "http-alt"}, {9200, "elasticsearch"}, {11211, "memcached"}, {27017, "mongodb"},
};

}  // namespace

std::string service_name(std::uint16_t port) {
    for (const auto& s : kServices)
        if (s.port == port) return s.name;
    return {};
}

std::vector<std::uint16_t> common_ports() {
    std::vector<std::uint16_t> v;
    for (const auto& s : kServices) v.push_back(s.port);
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
    return v;
}

}  // namespace sentinel
