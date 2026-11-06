// iOS 卡密验证 dylib（小白网络验证协议）
// 编译：xcrun --sdk iphoneos clang -arch arm64 -dynamiclib -fobjc-arc \
//         -framework Foundation -framework UIKit -mios-version-min=12.0 \
//         -o libkami.dylib kami.m xb_config.m
//
// 登录协议：AES-128-CBC(JSON) -> hex，sign = md5("123"+hex+"456"+软件秘钥+"789")
// 登录成功后定时心跳 /api/heartbeat；校验失败或超时直接 exit(0)。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <stdlib.h>
#import <stdio.h>
#import <string.h>

// ===== 由 xb_config.m 提供 =====
extern NSString *const XBSoft;
extern NSString *const XBSkey;
extern NSString *const XBAesKey;
extern NSString *const XBAesIv;
extern NSString *const XBSignTpl;
extern NSArray  *const XBEndpoints;
extern NSInteger const XBHeartSeconds;
extern BOOL      const XBHeartEnabled;

static NSString *const kPrefsCard = @"xb_kami";
static NSString *const kPrefsCookie = @"xb_cookie";
static NSString *const kPrefsClientId = @"xb_clientid";

#pragma mark - Crypto

static NSString *XBHexFromData(NSData *data) {
    const unsigned char *b = data.bytes;
    NSMutableString *s = [NSMutableString stringWithCapacity:data.length * 2];
    for (NSUInteger i = 0; i < data.length; i++) [s appendFormat:@"%02x", b[i]];
    return s;
}

static NSData *XBDataFromHex(NSString *hex) {
    NSInteger n = hex.length / 2;
    NSMutableData *d = [NSMutableData dataWithCapacity:n];
    for (NSInteger i = 0; i < n; i++) {
        unsigned int v = 0;
        sscanf([[hex substringWithRange:NSMakeRange(i * 2, 2)] UTF8String], "%x", &v);
        unsigned char c = (unsigned char)v;
        [d appendBytes:&c length:1];
    }
    return d;
}

static NSData *XBKeyData(void) {
    NSString *k = XBAesKey ?: @"";
    if (k.length < 16) k = @"HL1MAZDPXijHJqka";
    return [[k substringToIndex:16] dataUsingEncoding:NSUTF8StringEncoding];
}

static NSData *XBIVData(void) {
    NSString *v = XBAesIv ?: @"";
    if (v.length < 16) v = @"MyOuMMvnvSQsjOsN";
    return [[v substringToIndex:16] dataUsingEncoding:NSUTF8StringEncoding];
}

static NSString *XBAesEncryptHex(NSData *plain) {
    size_t outLen = plain.length + kCCBlockSizeAES128;
    NSMutableData *out = [NSMutableData dataWithLength:outLen];
    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                 XBKeyData().bytes, kCCKeySizeAES128, XBIVData().bytes,
                                 plain.bytes, plain.length, out.mutableBytes, outLen, &moved);
    if (st != kCCSuccess) return nil;
    out.length = moved;
    return XBHexFromData(out);
}

static NSData *XBAesDecryptHex(NSString *hex) {
    NSData *in = XBDataFromHex(hex);
    size_t outLen = in.length + kCCBlockSizeAES128;
    NSMutableData *out = [NSMutableData dataWithLength:outLen];
    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                 XBKeyData().bytes, kCCKeySizeAES128, XBIVData().bytes,
                                 in.bytes, in.length, out.mutableBytes, outLen, &moved);
    if (st != kCCSuccess) return nil;
    out.length = moved;
    return out;
}

static NSString *XBMD5Hex(NSString *s) {
    const char *c = [s UTF8String];
    unsigned char d[CC_MD5_DIGEST_LENGTH];
    CC_MD5(c, (CC_LONG)strlen(c), d);
    NSMutableString *out = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) [out appendFormat:@"%02x", d[i]];
    return out;
}

static NSString *XBRandomHex(int len) {
    const char *hx = "0123456789abcdef";
    NSMutableString *s = [NSMutableString stringWithCapacity:len];
    for (int i = 0; i < len; i++) [s appendFormat:@"%c", hx[arc4random_uniform(16)]];
    return s;
}

#pragma mark - Device

static NSString *XBFeature(void) {
    NSString *idfv = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
    idfv = [[idfv stringByReplacingOccurrencesOfString:@"-" withString:@""] lowercaseString];
    if (idfv.length < 8) idfv = [[NSUUID UUID].UUIDString stringByReplacingOccurrencesOfString:@"-" withString:@""];
    return [@"A" stringByAppendingString:idfv];
}

static NSString *XBClientId(void) {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSString *cid = [d stringForKey:kPrefsClientId];
    if (cid.length == 0) {
        cid = [[NSUUID UUID].UUIDString stringByReplacingOccurrencesOfString:@"-" withString:@""];
        [d setObject:cid forKey:kPrefsClientId];
    }
    return cid;
}

static NSString *XBDeviceMac(void) {
    NSString *md = XBMD5Hex(XBFeature());
    NSMutableString *mac = [NSMutableString string];
    for (int i = 0; i < 6; i++) {
        if (i > 0) [mac appendString:@":"];
        [mac appendString:[md substringWithRange:NSMakeRange(i * 2, 2)]];
    }
    return mac;
}

static NSString *XBClientOS(void) {
    return [@"iOS " stringByAppendingString:[[UIDevice currentDevice] systemVersion]];
}

static NSString *XBAppVersion(void) {
    NSString *v = [[NSBundle mainBundle] infoDictionary][@"CFBundleShortVersionString"];
    return v ?: @"1.0.0";
}

#pragma mark - License

@interface XbResult : NSObject
@property (nonatomic) BOOL success;
@property (nonatomic) NSInteger code;
@property (nonatomic, strong) NSString *msg;
@property (nonatomic, strong) NSString *cookie;
@end
@implementation XbResult
@end

static NSDictionary *XBBaseData(NSString *card) {
    return @{
        @"account": card ?: @"",
        @"account_pass": @"",
        @"feature": XBFeature(),
        @"mac": XBDeviceMac(),
        @"md5": @"",
        @"version": XBAppVersion(),
        @"clientid": XBClientId(),
        @"clientos": XBClientOS(),
        @"param": @"",
        @"token": XBRandomHex(32),
        @"uuid": XBRandomHex(32)
    };
}

static NSDictionary *XBPostBody(NSDictionary *data) {
    NSError *err = nil;
    NSData *json = [NSJSONSerialization dataWithJSONObject:data options:0 error:&err];
    if (!json) return nil;
    NSString *enc = XBAesEncryptHex(json);
    if (!enc) return nil;
    NSString *src = XBSignTpl ?: @"123[data]456[key]789";
    src = [src stringByReplacingOccurrencesOfString:@"[data]" withString:enc];
    src = [src stringByReplacingOccurrencesOfString:@"[key]" withString:(XBSkey ?: @"")];
    return @{ @"soft": XBSoft ?: @"", @"data": enc, @"sign": XBMD5Hex(src) };
}

static NSDictionary *XBHttpPostSync(NSString *url, NSDictionary *body) {
    NSError *err = nil;
    NSData *payload = [NSJSONSerialization dataWithJSONObject:body options:0 error:&err];
    if (!payload) return nil;
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 12.0;
    [req setValue:@"application/json; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    [req setValue:@"okhttp/4.9.0" forHTTPHeaderField:@"User-Agent"];
    req.HTTPBody = payload;

    __block NSData *respData = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            respData = d;
            dispatch_semaphore_signal(sem);
        }];
    [task resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(14.0 * NSEC_PER_SEC)));
    if (!respData) return nil;
    id obj = [NSJSONSerialization JSONObjectWithData:respData options:0 error:&err];
    return [obj isKindOfClass:[NSDictionary class]] ? obj : nil;
}

static NSDictionary *XBPostFirst(NSArray *urls, NSDictionary *body) {
    for (NSString *u in urls) {
        if ([u isKindOfClass:[NSString class]] && u.length > 0) {
            NSDictionary *root = XBHttpPostSync(u, body);
            if (root) return root;
        }
    }
    return nil;
}

static NSDictionary *XBParseRoot(NSDictionary *root, XbResult *res) {
    if (!root) { res.success = NO; res.code = -1; res.msg = @"网络连接失败"; return nil; }
    if (![root[@"status"] isEqual:@"success"]) {
        res.success = NO; res.code = -1;
        NSString *m = root[@"msg"];
        res.msg = (m.length > 0) ? m : @"服务器拒绝";
        return nil;
    }
    NSString *hex = root[@"data"];
    if (![hex isKindOfClass:[NSString class]] || hex.length == 0) {
        res.success = NO; res.code = -1; res.msg = @"响应数据异常"; return nil;
    }
    NSData *dec = XBAesDecryptHex(hex);
    if (!dec) { res.success = NO; res.code = -1; res.msg = @"数据解密失败"; return nil; }
    id inner = [NSJSONSerialization JSONObjectWithData:dec options:0 error:nil];
    return [inner isKindOfClass:[NSDictionary class]] ? inner : nil;
}

static NSArray *XBHeartbeatURLs(void) {
    NSMutableArray *out = [NSMutableArray array];
    for (id u in XBEndpoints) {
        if (![u isKindOfClass:[NSString class]]) continue;
        NSString *s = u;
        if ([s rangeOfString:@"/api/login"].location != NSNotFound) {
            s = [s stringByReplacingOccurrencesOfString:@"/api/login" withString:@"/api/heartbeat"];
        }
        [out addObject:s];
    }
    return out;
}

static XbResult *XBLogin(NSString *card) {
    XbResult *res = [XbResult new];
    NSDictionary *body = XBPostBody(XBBaseData(card));
    res.success = NO; res.code = -1; res.msg = @"验证失败";
    if (!body) { res.msg = @"本地加密失败"; return res; }
    NSDictionary *root = XBPostFirst(XBEndpoints, body);
    NSDictionary *inner = XBParseRoot(root, res);
    if (!inner) { if (res.msg.length == 0) res.msg = @"验证失败"; return res; }
    res.code = [inner[@"code"] integerValue];
    NSString *m = inner[@"msg"];
    if (m.length > 0) res.msg = m;
    res.success = (res.code == 200);
    id cookie = inner[@"cookie"];
    if (!cookie) {
        id result = inner[@"result"];
        if ([result isKindOfClass:[NSDictionary class]]) cookie = result[@"cookie"];
    }
    if ([cookie isKindOfClass:[NSString class]]) res.cookie = cookie;
    if (res.success && (res.msg.length == 0)) res.msg = @"验证成功";
    return res;
}

static XbResult *XBHeartbeat(NSString *card, NSString *cookie) {
    XbResult *res = [XbResult new];
    NSMutableDictionary *data = [XBBaseData(card) mutableCopy];
    if (cookie.length > 0) data[@"cookie"] = cookie;
    NSDictionary *body = XBPostBody(data);
    res.success = NO; res.code = -1; res.msg = @"验证失败";
    if (!body) return res;
    NSDictionary *root = XBPostFirst(XBHeartbeatURLs(), body);
    NSDictionary *inner = XBParseRoot(root, res);
    if (!inner) return res;
    res.code = [inner[@"code"] integerValue];
    NSString *m = inner[@"msg"];
    if (m.length > 0) res.msg = m;
    res.success = (res.code == 200);
    return res;
}

#pragma mark - Heartbeat

static NSUserDefaults *XBPrefs(void) { return [NSUserDefaults standardUserDefaults]; }

static void XBDie(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        exit(0);
    });
    exit(0);
}

static void XBStartHeartbeat(NSString *card) {
    if (!XBHeartEnabled) return;
    NSInteger sec = XBHeartSeconds;
    if (sec < 10) sec = 150;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
        [NSThread sleepForTimeInterval:sec];
        while (YES) {
            @autoreleasepool {
                NSString *saved = [XBPrefs() stringForKey:kPrefsCard];
                NSString *useCard = (card.length > 0) ? card : saved;
                NSString *cookie = [XBPrefs() stringForKey:kPrefsCookie];
                BOOL ok = NO;
                if (useCard.length > 0) {
                    if (cookie.length > 0) {
                        XbResult *r = XBHeartbeat(useCard, cookie);
                        if (r.success) {
                            ok = YES;
                        } else {
                            XbResult *re = XBLogin(useCard);
                            if (re.success) {
                                ok = YES;
                                if (re.cookie.length > 0) [XBPrefs() setObject:re.cookie forKey:kPrefsCookie];
                            }
                        }
                    } else {
                        XbResult *r = XBLogin(useCard);
                        ok = r.success;
                        if (r.success && r.cookie.length > 0) [XBPrefs() setObject:r.cookie forKey:kPrefsCookie];
                    }
                }
                if (!ok) { XBDie(); return; }
            }
            [NSThread sleepForTimeInterval:sec];
        }
    });
}

#pragma mark - Login UI

@class XbLoginViewController;
static XbLoginViewController *gLoginVC = nil;

@interface XbLoginViewController : UIViewController
@property (nonatomic, strong) UITextField *field;
@property (nonatomic, strong) UIButton *button;
@property (nonatomic, strong) UILabel *status;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;
@property (nonatomic) BOOL busy;
@end

@implementation XbLoginViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithRed:0.956 green:0.965 blue:0.984 alpha:1.0];

    CAGradientLayer *bg = [CAGradientLayer layer];
    bg.frame = self.view.bounds;
    bg.colors = @[(__bridge id)[UIColor colorWithRed:0.0 green:0.478 blue:1.0 alpha:1.0].CGColor,
                  (__bridge id)[UIColor colorWithRed:0.0 green:0.667 blue:1.0 alpha:1.0].CGColor];
    bg.startPoint = CGPointMake(0, 0);
    bg.endPoint = CGPointMake(1, 1);
    [self.view.layer insertSublayer:bg atIndex:0];
    self.view.tag = 9991;

    [self buildUI];
}

- (void)buildUI {
    CGFloat w = self.view.bounds.size.width;
    CGFloat cw = MIN(w - 48, 360);
    CGFloat x = (w - cw) / 2;
    CGFloat y = self.view.bounds.size.height * 0.30;

    UIView *card = [[UIView alloc] initWithFrame:CGRectMake(x, y, cw, 300)];
    card.backgroundColor = [UIColor whiteColor];
    card.layer.cornerRadius = 16;
    card.layer.shadowColor = [UIColor blackColor].CGColor;
    card.layer.shadowOpacity = 0.18;
    card.layer.shadowRadius = 18;
    card.layer.shadowOffset = CGSizeMake(0, 8);
    card.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin;
    [self.view addSubview:card];

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 24, cw - 40, 28)];
    title.text = @"授权验证";
    title.font = [UIFont boldSystemFontOfSize:19];
    title.textColor = [UIColor colorWithWhite:0.13 alpha:1.0];
    [card addSubview:title];

    UILabel *sub = [[UILabel alloc] initWithFrame:CGRectMake(20, 54, cw - 40, 18)];
    sub.text = @"请输入卡密后点击验证";
    sub.font = [UIFont systemFontOfSize:13];
    sub.textColor = [UIColor colorWithWhite:0.6 alpha:1.0];
    [card addSubview:sub];

    self.field = [[UITextField alloc] initWithFrame:CGRectMake(20, 86, cw - 40, 46)];
    self.field.placeholder = @"请输入卡密";
    self.field.borderStyle = UITextBorderStyleRoundedRect;
    self.field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    self.field.autocorrectionType = UITextAutocorrectionTypeNo;
    self.field.clearButtonMode = UITextFieldViewModeWhileEditing;
    self.field.returnKeyType = UIReturnKeyDone;
    [card addSubview:self.field];

    self.button = [UIButton buttonWithType:UIButtonTypeSystem];
    self.button.frame = CGRectMake(20, 150, cw - 40, 48);
    [self.button setTitle:@"立即验证 →" forState:UIControlStateNormal];
    [self.button setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.button.titleLabel.font = [UIFont boldSystemFontOfSize:16];
    self.button.backgroundColor = [UIColor colorWithRed:0.0 green:0.478 blue:1.0 alpha:1.0];
    self.button.layer.cornerRadius = 10;
    [self.button addTarget:self action:@selector(onVerify) forControlEvents:UIControlEventTouchUpInside];
    [card addSubview:self.button];

    self.status = [[UILabel alloc] initWithFrame:CGRectMake(20, 208, cw - 40, 18)];
    self.status.font = [UIFont systemFontOfSize:13];
    self.status.textColor = [UIColor colorWithWhite:0.55 alpha:1.0];
    self.status.textAlignment = NSTextAlignmentCenter;
    [card addSubview:self.status];

    self.spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
    self.spinner.center = CGPointMake(cw / 2, 250);
    self.spinner.hidesWhenStopped = YES;
    [card addSubview:self.spinner];

    UILabel *copy = [[UILabel alloc] initWithFrame:CGRectMake(x, y + 316, cw, 18)];
    copy.text = @"木子插件 © 2026";
    copy.font = [UIFont systemFontOfSize:12];
    copy.textColor = [UIColor colorWithWhite:1.0 alpha:0.9];
    copy.textAlignment = NSTextAlignmentCenter;
    copy.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin;
    [self.view addSubview:copy];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    NSString *saved = [XBPrefs() stringForKey:kPrefsCard];
    if (saved.length > 0) {
        self.field.text = saved;
        [self doVerify:saved silent:YES];
    }
}

- (void)onVerify {
    if (self.busy) return;
    [self.field resignFirstResponder];
    NSString *card = [self.field.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (card.length == 0) { self.status.text = @"请输入卡密"; return; }
    [self doVerify:card silent:NO];
}

- (void)doVerify:(NSString *)card silent:(BOOL)silent {
    if (self.busy) return;
    self.busy = YES;
    self.button.enabled = NO;
    [self.button setTitle:@"验证中..." forState:UIControlStateNormal];
    self.status.text = @"正在连接服务器...";
    [self.spinner startAnimating];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        XbResult *r = XBLogin(card);
        dispatch_async(dispatch_get_main_queue(), ^{
            self.busy = NO;
            self.button.enabled = YES;
            [self.button setTitle:@"立即验证 →" forState:UIControlStateNormal];
            [self.spinner stopAnimating];
            if (r.success) {
                [XBPrefs() setObject:card forKey:kPrefsCard];
                if (r.cookie.length > 0) [XBPrefs() setObject:r.cookie forKey:kPrefsCookie];
                self.status.text = @"验证成功";
                XBStartHeartbeat(card);
                [self dismissViewControllerAnimated:NO completion:^{
                    gLoginVC = nil;
                }];
            } else {
                self.status.text = r.msg.length > 0 ? r.msg : @"验证失败";
                if (!silent) {
                    CGFloat cx = self.field.center.x;
                    [UIView animateWithDuration:0.07 animations:^{
                        self.field.center = CGPointMake(cx - 8, self.field.center.y);
                    } completion:^(BOOL f) {
                        [UIView animateWithDuration:0.07 animations:^{
                            self.field.center = CGPointMake(cx + 8, self.field.center.y);
                        } completion:^(BOOL f2) {
                            [UIView animateWithDuration:0.07 animations:^{
                                self.field.center = CGPointMake(cx, self.field.center.y);
                            }];
                        }];
                    }];
                }
            }
        });
    });
}

@end

static UIWindow *XBKeyWindow(void) {
    for (UIWindow *w in [UIApplication sharedApplication].windows) {
        if (w.isKeyWindow) return w;
    }
    return [UIApplication sharedApplication].keyWindow;
}

static void XBTryPresent(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (gLoginVC) return;
        UIWindow *win = XBKeyWindow();
        UIViewController *root = win.rootViewController;
        if (!root) return;
        if (root.presentedViewController) {
            // 已经在展示别的界面，稍后再试
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                XBTryPresent();
            });
            return;
        }
        XbLoginViewController *vc = [XbLoginViewController new];
        vc.modalPresentationStyle = UIModalPresentationFullScreen;
        gLoginVC = vc;
        [root presentViewController:vc animated:NO completion:nil];
    });
}

__attribute__((constructor))
static void XBInit(void) {
    @autoreleasepool {
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                          object:nil queue:[NSOperationQueue mainQueue]
                                                      usingBlock:^(NSNotification *n) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                XBTryPresent();
            });
        }];
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                          object:nil queue:[NSOperationQueue mainQueue]
                                                      usingBlock:^(NSNotification *n) {
            XBTryPresent();
        }];
    }
}
