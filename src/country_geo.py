"""Approximate country centres (lat, lon) used to sort the country list by distance."""
import math

_RAW = (
    "AD:42.5,1.5|AE:24,54|AF:33,65|AG:17,-61.8|AL:41,20|AM:40,45|AO:-12,18|AR:-34,-64|AT:47.5,14|AU:-25,134|"
    "AZ:40.3,47.7|BA:44,18|BB:13.2,-59.5|BD:24,90|BE:50.6,4.6|BF:12,-1.5|BG:42.7,25|BH:26,50.5|BI:-3.4,29.9|"
    "BJ:9.5,2.3|BN:4.5,114.7|BO:-17,-65|BR:-10,-52|BS:25,-77.4|BT:27.5,90.4|BW:-22,24|BY:53.7,28|BZ:17.2,-88.7|"
    "CA:56,-100|CD:-3,23|CF:6.6,20.9|CG:-1,15.8|CH:46.8,8.2|CI:7.5,-5.5|CL:-33,-71|CM:6,12.5|CN:35,103|"
    "CO:4,-72|CR:10,-84|CU:21.5,-79|CV:16,-24|CY:35,33|CZ:49.8,15.5|DE:51,10|DJ:11.8,42.6|DK:56,10|"
    "DM:15.4,-61.4|DO:19,-70.7|DZ:28,3|EC:-1.8,-78|EE:58.6,25|EG:26,30|ER:15.2,39.8|ES:40,-4|ET:9,40|"
    "FI:64,26|FJ:-17.7,178|FR:46.6,2.2|GA:-0.8,11.6|GB:54,-2|GD:12.1,-61.7|GE:42,43.5|GH:8,-1.2|GM:13.5,-15.4|"
    "GN:10.9,-10.9|GQ:1.7,10.3|GR:39,22|GT:15.5,-90.3|GW:12,-15|GY:5,-59|HK:22.3,114.2|HN:15,-86.6|HR:45.1,15.2|"
    "HT:19,-72.4|HU:47,19.5|ID:-2,118|IE:53,-8|IL:31.5,34.9|IN:22,79|IQ:33,44|IR:32,53|IS:65,-18|IT:42.8,12.8|"
    "JM:18.1,-77.3|JO:31,36.5|JP:36,138|KE:0.5,38|KG:41.5,74.6|KH:12.6,104.9|KM:-11.9,43.9|KN:17.3,-62.7|"
    "KP:40,127|KR:36.5,128|KW:29.3,47.6|KZ:48,68|LA:18.5,104|LB:33.9,35.9|LC:13.9,-61|LI:47.2,9.5|LK:7.9,80.7|"
    "LR:6.4,-9.4|LS:-29.6,28.2|LT:55.3,23.9|LU:49.8,6.1|LV:56.9,24.6|LY:27,17|MA:32,-6|MC:43.7,7.4|MD:47,28.5|"
    "ME:42.7,19.3|MG:-19,47|MK:41.6,21.7|ML:17.6,-4|MM:21,96|MN:46.9,103.8|MO:22.2,113.5|MR:20,-10.9|"
    "MT:35.9,14.4|MU:-20.3,57.6|MV:3.2,73.2|MW:-13.3,34.3|MX:23.6,-102.5|MY:4.2,102|MZ:-18.7,35.5|NA:-22,17|"
    "NE:17.6,8|NG:9,8|NI:12.9,-85|NL:52.2,5.3|NO:62,10|NP:28,84|NZ:-41,174|OM:21.5,55.9|PA:8.5,-80|PE:-10,-76|"
    "PG:-6,144|PH:12.9,122|PK:30,70|PL:52,19|PR:18.2,-66.5|PS:31.9,35.2|PT:39.5,-8|PY:-23,-58|QA:25.3,51.2|"
    "RO:46,25|RS:44,21|RU:57,45|RW:-2,29.9|SA:24,45|SB:-9.6,160|SC:-4.7,55.5|SD:15,30|SE:62,15|SG:1.35,103.8|"
    "SI:46.1,14.8|SK:48.7,19.7|SL:8.5,-11.8|SM:43.9,12.5|SN:14.5,-14.5|SO:6,46|SR:4,-56|SS:7,30|SV:13.8,-88.9|"
    "SY:35,38|SZ:-26.5,31.5|TD:15,19|TG:8.6,0.8|TH:15,101|TJ:38.9,71|TL:-8.8,125.7|TM:39,59.6|TN:34,9|TR:39,35|"
    "TT:10.7,-61.2|TW:23.7,121|TZ:-6.4,34.9|UA:49,32|UG:1.4,32.3|US:39,-98|UY:-33,-56|UZ:41.4,64.6|"
    "VA:41.9,12.45|VE:7,-66|VN:16,106|VU:-16,167|WS:-13.6,-172.4|XK:42.6,20.9|YE:15.6,48|ZA:-29,24|ZM:-13.1,27.8|"
    "ZW:-19,29.9|AW:12.5,-70|BM:32.3,-64.8|GG:49.5,-2.6|GI:36.1,-5.35|GL:72,-40|GU:13.4,144.8|IM:54.2,-4.5|"
    "JE:49.2,-2.1|KY:19.3,-81.2|NC:-21.3,165.5|PF:-17.7,-149.4|RE:-21.1,55.5|VG:18.4,-64.6|VI:18.3,-64.9|"
    "FO:62,-6.8|AX:60.2,20"
)
CENTERS = {k: tuple(float(x) for x in v.split(",")) for k, v in (p.split(":") for p in _RAW.split("|"))}


def distance_km(a, b):
    la1, lo1 = map(math.radians, CENTERS[a])
    la2, lo2 = map(math.radians, CENTERS[b])
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 12742 * math.asin(math.sqrt(h))


def home_country(default="LV"):
    """The country set in Windows regional settings (falls back to default)."""
    try:
        import ctypes
        gid = ctypes.windll.kernel32.GetUserGeoID(16)  # GEOCLASS_NATION
        buf = ctypes.create_unicode_buffer(8)
        if ctypes.windll.kernel32.GetGeoInfoW(gid, 4, buf, 8, 0) and buf.value in CENTERS:  # GEO_ISO2
            return buf.value
    except Exception:
        pass
    return default
