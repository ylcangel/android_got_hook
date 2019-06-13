/*
 *
 * Android Got Hook
 *
 * Author : sp00f
 * Version 0.1
 */
 
#ifndef GOTHOOK_H_
#define GOTHOOK_H_
 
#include <android/log.h>
#define ALOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "LOG", __VA_ARGS__))
 
 
/**
 * Function : GotHook
 * @param libName - will got hook 's so name
 * @param symbol  - will hook import method symbol
 * @param oldAddr - the method addr before hooked
 * @param newAddr - will replace the new addr of the method
 *
 * @return success true ,else false
 */
bool gotHook(const char* libName, const char* symbol, void* oldAddr, void* newAddr);
 
#endif /* GOTHOOK_H_ */
