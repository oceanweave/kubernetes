/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// apiserver is the main api server and master for the cluster.
// it is responsible for serving the cluster management API.
package main

import (
	"os"
	_ "time/tzdata" // for timeZone support in CronJob

	"k8s.io/component-base/cli"
	_ "k8s.io/component-base/logs/json/register"          // for JSON log format registration
	_ "k8s.io/component-base/metrics/prometheus/clientgo" // load all the prometheus client-go plugins
	_ "k8s.io/component-base/metrics/prometheus/version"  // for version metric registration
	"k8s.io/kubernetes/cmd/kube-apiserver/app"
)

func main() {
	// dfy: 构建 apiserver 参数读取命令
	command := app.NewAPIServerCommand()
	/* dfy:
	在 Cobra 中，Run 函数和 RunE 函数是可以共存的，但是它们不会同时执行。
	当你执行一个 Cobra 命令时，Cobra 会按照以下规则执行其中一个：
	1. 如果存在 Run 函数： Cobra 将执行 Run 函数，忽略 RunE。
	2. 如果存在 RunE 函数但不存在 Run 函数： Cobra 将执行 RunE 函数。
	这意味着，如果同时存在 Run 和 RunE 函数，Cobra 会优先选择执行 Run 函数。只有在不存在 Run 函数时，才会考虑执行 RunE 函数。
	*/
	code := cli.Run(command)
	os.Exit(code)
}
