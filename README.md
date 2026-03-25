# originrecon

A powerful tool for finding the real origin IP of a website hidden behind a CDN or WAF (such as Cloudflare or AWS CloudFront).

> ⭐ This is an updated version of the original [hakoriginfinder](https://github.com/hakluke/hakoriginfinder) by [hakluke](https://github.com/hakluke). Full credit to hakluke for the original concept and implementation.

---

## New Features (vs original)

- **SSL Certificate Info** — automatically displays `CN` and `Organization` from SSL cert beside every result
- **Match String** (`-mr`) — optional flag to highlight results where a specific string is found in the response body (shown in magenta/bold)

---

## Installation

```bash
go install github.com/0xmaruf/originrecon@latest
```

---

## Usage

```bash
prips CIDR_RANGE | originrecon -h https://target.com [options]
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-h` | Target URL e.g. `https://target.com` | required |
| `-l` | Levenshtein threshold, higher = more lenient | `5` |
| `-p` | Comma separated ports to scan | `80,443` |
| `-t` | Number of threads | `32` |
| `-mr` | Optional match string to find in response body | `""` |

---

## Examples

**Basic usage:**
```bash
prips 18.67.233.0/24 | originrecon -h https://target.com -l 3
```

**With match string:**
```bash
prips 18.67.233.0/24 | originrecon -h https://target.com -l 3 -mr "Admin Panel"
```

**Custom ports:**
```bash
prips 18.67.233.0/24 | originrecon -h https://target.com -p 80,443,8080,8443
```

---

## Output

```
[*] Fetching original URL: https://target.com
[*] Got original response (1234 bytes)

MATCH https://1.2.3.4:443 [CN=*.target.com | O=Target Company] 0
NOMATCH https://1.2.3.5:443 [CN=*.other.com | O=Other Company] 220
BODY-MATCH https://1.2.3.6:443 [CN=*.target.com | O=Target Company] (distance:0) matched: "Admin Panel"
```

### Color coding:
- 🟢 **Green** = MATCH (response similar to target)
- 🟣 **Magenta/Bold** = BODY-MATCH (match string found in response)
- ⚪ **White** = NOMATCH

---

## How to find CDN IP ranges

**AWS CloudFront:**
```bash
curl https://ip-ranges.amazonaws.com/ip-ranges.json | python3 -c "
import json,sys
data=json.load(sys.stdin)
cf=[x for x in data['prefixes'] if x['service']=='CLOUDFRONT']
for x in cf: print(x['ip_prefix'])
"
```

**Cloudflare:**
```
https://www.cloudflare.com/ips-v4
https://www.cloudflare.com/ips-v6
```

---

## Credits

- Original tool: [hakoriginfinder](https://github.com/hakluke/hakoriginfinder) by [hakluke](https://github.com/hakluke)
- This version adds SSL certificate display and body match string feature

---

## Disclaimer

This tool is intended for use in authorized bug bounty programs and penetration testing engagements only. Always ensure you have permission before testing any target.
