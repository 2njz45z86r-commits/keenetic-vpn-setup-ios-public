#import "EngineBridge.h"
#import <Mobile/Mobile.h>

NSString *KSetupStart(void) {
    NSError *error = nil;
    NSString *url = MobileStart(&error);
    return error == nil ? url : nil;
}

void KSetupStop(void) {
    MobileStop();
}
