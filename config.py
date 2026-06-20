# config.py

# الأذونات الخطيرة
DANGEROUS_PERMISSIONS = [
    "SYSTEM_ALERT_WINDOW",
    "BIND_ACCESSIBILITY_SERVICE",
    "REQUEST_INSTALL_PACKAGES",
    "READ_PHONE_STATE",
    "RECORD_AUDIO",
    "CAMERA",
    "READ_SMS",
    "SEND_SMS",
    "ACCESS_FINE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION",
    "GET_ACCOUNTS",
    "READ_CONTACTS",
    "PACKAGE_USAGE_STATS"
]

# مكتبات الإعلانات الشائعة
AD_LIBRARIES = [
    "com.google.android.gms.ads",
    "com.facebook.ads",
    "com.applovin",
    "com.unity3d.ads",
    "com.adcolony",
    "com.vungle",
    "com.startapp",
    "com.ironsource",
    "com.google.ads",
    "com.amazon.device.ads",
    "com.inmobi",
    "com.chartboost",
    "com.tapjoy",
    "com.flurry.android"
]

# خوادم إعلانات معروفة (لتحليل الشبكة)
AD_SERVERS = [
    "ads.google.com",
    "doubleclick.net",
    "facebook.com/ads",
    "adservice.google.com",
    "pagead2.googlesyndication.com",
    "adserver.adtech.de",
    "c.amazon-adsystem.com",
    "ads.pubmatic.com",
    "adnxs.com",
    "bidswitch.net",
    "openx.net",
    "rubiconproject.com",
    "applovin.com",
    "unityads.unity3d.com"
]

# ===== قائمة التطبيقات الموثوقة (حتى لو بها إعلانات) =====
TRUSTED_APPS = [
    # Google
    "com.google.android",
    "com.google.android.gms",
    "com.google.android.apps",
    "com.google.android.youtube",
    "com.google.android.gm",
    "com.google.android.apps.maps",
    "com.google.android.apps.docs",
    "com.google.android.apps.photos",
    "com.google.android.calendar",
    "com.google.android.contacts",
    
    # Meta (Facebook)
    "com.facebook.katana",
    "com.facebook.orca",
    "com.facebook.lite",
    "com.facebook.system",
    "com.facebook.services",
    "com.facebook.appmanager",
    
    # Messaging
    "com.whatsapp",
    "org.telegram.messenger",
    "com.instagram.android",
    "com.instagram.lite",
    "com.snapchat.android",
    "com.snapchat.lite",
    
    # Microsoft
    "com.microsoft.appmanager",  # Added
    "com.microsoft.office",
    "com.microsoft.teams",
    "com.microsoft.outlook",
    
    # Popular known apps
    "com.truecaller",  # Added
    "com.pinterest",
    "com.openai.chatgpt",
    "com.deepseek.chat",
    "com.spotify.music",
    "com.netflix.mediaclient",
    "com.tiktok.android",
    "com.twitter.android",
    "com.reddit.frontpage",
    
    # Utility
    "ru.zdevs.zarchiver",  # Added
    "mark.via.gp",  # Added
    "com.clover.secscanner",  # Added
    "com.apkpure.aegon",  # Added
    "com.happymod.apk",  # Added
    "com.snaptube.premium",  # Added
    "shareit.lite",  # Added
    "io.telda.app",  # Added
    "com.lge.app1",  # Added
    "com.truedevelopersstudio.automatictap.autoclicker",  # Added
    "com.facebook.services",  # Added
    "com.gallery20",  # Added
    "com.cybercat.acbridge",  # Added
    "com.hoffnung",  # Added
    "com.reallytek.wg",  # Added
    "com.wo.voice2",  # Added
    "com.fpsensor_sample.fpSensorExtensionSvc2",  # Added
    "com.transsnet.store",  # Added
    "app.likestory.premium",  # Added
    "com.rlk.mi",  # Added
    "com.cdfinger.factorytest",  # Added
    "net.bat.store",  # Added
    "com.sh.smart.caller",  # Added
    "com.ucare.we",  # Added
    "com.jupiter.tornado",  # Added
    "com.calculator.hideu",  # Added
    "com.example",  # Added
    "com.example.android.notepad",  # Added
    "com.mtk.telephony",  # Added
    
    # Huawei system apps
    "com.huawei.camera",
    "com.huawei.android.launcher",
    "com.huawei.hidisk",
    "com.huawei.android.thememanager",
    "com.huawei.motionservice",
    "com.huawei.android.FMRadio",
    "com.huawei.android.totemweather",
    "com.nuance.swype.emui",
    "com.ontim.legalInfo",
    "com.huawei.KoBackup",
    "com.ontim.deviceinfo",
    "androidhwext",
    "com.huawei.hwvplayer",
    "com.ontime.simlockwriteap",
    "com.huawei.android.internal.app",
    "com.huawei.systemmanager",
    "com.huawei.hwstartupguide",
    "com.huawei.qrcode.dispatcher",
    "com.huawei.android.hwouc",
    "com.huawei.android.wfdft",
    "com.huawei.powergenie",
    "com.ontim.cit"
]

# ===== قائمة استبعاد تطبيقات النظام =====
SYSTEM_PACKAGES = [
    # Android
    "com.android",
    "com.android.providers",
    "com.android.settings",
    "com.android.systemui",
    "com.android.phone",
    "com.android.mms",
    "com.android.camera",
    "com.android.gallery",
    "com.android.contacts",
    "com.android.calendar",
    "com.android.documentsui",
    "com.android.externalstorage",
    "com.android.bluetooth",
    "com.android.inputdevices",
    "com.android.keychain",
    "com.android.pacprocessor",
    "com.android.certinstaller",
    "com.android.managedprovisioning",
    "com.android.statementservice",
    "com.android.cts",
    "com.android.egg",
    "com.android.stk",
    "com.android.backupconfirm",
    "com.android.shell",
    "com.android.traceur",
    "com.android.wallpaperbackup",
    "com.android.defcontainer",
    "com.android.htmlviewer",
    "com.android.simappdialog",
    "com.android.captiveportallogin",
    "com.android.companiondevicemanager",
    "com.android.wallpapercropper",
    "com.android.wallpaperpicker",
    "com.android.bookmarkprovider",
    "com.android.vpndialogs",
    "com.android.bips",
    "com.android.printspooler",
    "com.android.sharedstoragebackup",
    "com.android.calllogbackup",
    "com.android.proxyhandler",
    "com.android.smspush",
    "com.android.storagemanager",
    "com.android.carrierconfig",
    "com.android.emergency",
    "com.android.location.fused",
    "com.android.providers.blockednumber",
    "com.android.providers.userdictionary",
    "com.android.providers.partnerbookmarks",
    "com.android.cellbroadcastreceiver",
    "com.android.incallui",
    "com.android.server.telecom",
    "com.android.mtp",
    "com.android.se",
    "com.android.pacprocessor",
    "com.android.cts.priv.ctsshim",
    "com.android.cts.ctsshim",
    "com.android.defcontainer",
    "com.android.pacprocessor",
    "com.android.statementservice",
    
    # Google
    "com.google.android",
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.google.android.apps",
    "com.google.android.setupwizard",
    "com.google.android.configupdater",
    "com.google.android.onetimeinitializer",
    "com.google.android.packageinstaller",
    "com.google.android.syncadapters",
    "com.google.android.webview",
    "com.google.android.tts",
    "com.google.android.ims",
    "com.google.android.feedback",
    "com.google.android.printservice",
    "com.google.android.backuptransport",
    "com.google.android.ext.services",
    "com.google.android.ext.shared",
    "com.google.android.packageinstaller",
    "com.google.android.gsf",
    "com.google.android.webview",
    
    # MediaTek
    "com.mediatek",
    "com.mediatek.engineermode",
    "com.mediatek.omacp",
    "com.mediatek.ims",
    "com.mediatek.gba",
    "com.mediatek.schpwronoff",
    "com.mediatek.ygps",
    "com.mediatek.simprocessor",
    "com.mediatek.location",
    "com.mediatek.lbs",
    "com.mediatek.providers.drm",
    "com.mediatek.batterywarning",
    "com.mediatek.nlpservice",
    "com.mediatek.callrecorder",
    "com.mediatek.mtklogger",
    "com.mediatek.atmwifimeta",
    "com.mediatek.location.mtknlp",
    
    # Transsion / Infinix
    "com.transsion",
    "com.transsion.phonemaster",
    "com.transsion.camera",
    "com.transsion.XOSLauncher",
    "com.transsion.phonemanager",
    "com.transsion.applock",
    "com.transsion.fmradio",
    "com.transsion.powercenter",
    "com.transsion.readmode",
    "com.transsion.magicfont",
    "com.transsion.agingfunction",
    "com.transsion.aogservice",
    "com.transsion.theme.icon",
    "com.transsion.faceid",
    "com.transsion.microintelligence",
    "com.transsion.smartpanel",
    "com.transsion.keyguardgesture",
    "com.transsion.systemupdate",
    "com.transsion.soundrecorder",
    "com.transsion.calculator",
    "com.transsion.deskclock",
    "com.transsion.compass",
    "com.transsion.overlaysuw",
    "com.transsion.videocallenhancer",
    "com.transsion.aibox",
    "com.infinix",
    "com.tecno",
    "com.itel",
    
    # Huawei system apps
    "com.huawei.camera",
    "com.huawei.android.launcher",
    "com.huawei.hidisk",
    "com.huawei.android.thememanager",
    "com.huawei.motionservice",
    "com.huawei.android.FMRadio",
    "com.huawei.android.totemweather",
    "com.nuance.swype.emui",
    "com.ontim.legalInfo",
    "com.huawei.KoBackup",
    "com.ontim.deviceinfo",
    "androidhwext",
    "com.huawei.hwvplayer",
    "com.ontime.simlockwriteap",
    "com.huawei.android.internal.app",
    "com.huawei.systemmanager",
    "com.huawei.hwstartupguide",
    "com.huawei.qrcode.dispatcher",
    "com.huawei.android.hwouc",
    "com.huawei.android.wfdft",
    "com.huawei.powergenie",
    "com.ontim.cit",
    "com.huawei.android.launcher",
    "com.huawei.android.hwucf",
    "com.huawei.android.hwvplayer",
    "com.huawei.hihealth",
    "com.huawei.hms",
    "com.huawei.hwid",
    "com.huawei.appmarket",
    "com.huawei.android.wfdft",
    "com.huawei.phoneservice",
    "com.huawei.trustcircle",
    
    # Other system-level
    "com.mediatek.mtklogger",
    "com.mediatek.engineermode",
    "com.mediatek.lbs",
    "com.mediatek.location",
    "com.mediatek.ims",
    "com.mediatek.simprocessor",
    "com.mediatek.gba",
    "com.mediatek.schpwronoff",
    "com.mediatek.ygps",
    "com.mediatek.providers.drm",
    "com.mediatek.batterywarning",
    "com.mediatek.nlpservice",
    "com.mediatek.callrecorder",
    "com.mediatek.atmwifimeta",
    "com.mediatek.location.mtknlp"
]

# ===== قواعد Quark محسّنة =====
QUARK_RULES = [
    {
        "pattern": "SYSTEM_ALERT_WINDOW",
        "description": "Display overlay windows (often used for ads)",
        "confidence": 70,
        "malicious_threshold": 80
    },
    {
        "pattern": "ACCESSIBILITY_SERVICE",
        "description": "Can click automatically (may be abused)",
        "confidence": 80,
        "malicious_threshold": 85
    },
    {
        "pattern": "BOOT_COMPLETED",
        "description": "Starts automatically on boot",
        "confidence": 60,
        "malicious_threshold": 70
    },
    {
        "pattern": "INTERNET",
        "description": "Network access",
        "confidence": 30,
        "malicious_threshold": 50
    },
    {
        "pattern": "READ_PHONE_STATE",
        "description": "Reads device identity",
        "confidence": 40,
        "malicious_threshold": 60
    }
]