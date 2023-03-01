/*
Copyright 2018 The Kubernetes Authors.

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

package cache

import (
	"fmt"

	"k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	utilnode "k8s.io/kubernetes/pkg/util/node"
)

// nodeTree is a tree-like data structure that holds node names in each zone. Zone names are
// keys to "NodeTree.tree" and values of "NodeTree.tree" are arrays of node names.
// NodeTree is NOT thread-safe, any concurrent updates/reads from it must be synchronized by the caller.
// It is used only by schedulerCache, and should stay as such.
type nodeTree struct {
	// dfy： key 为 topology key，value 为在此 topology key 下的 所有 nodes
	tree map[string]*nodeArray // a map from zone (region-zone) to an array of nodes in the zone.
	// dfy: zones 可以理解为 topology key 集合，就是有多少种拓扑
	zones []string // a list of all the zones in the tree (keys)
	// dfy: 记录遍历 zones 数据，遍历到的位置
	zoneIndex int
	numNodes  int
}

// nodeArray is a struct that has nodes that are in a zone.
// We use a slice (as opposed to a set/map) to store the nodes because iterating over the nodes is
// a lot more frequent than searching them by name.
type nodeArray struct {
	nodes []string
	// dfy: lastIndex 记录遍历当前 nodes 数组，遍历的位置
	lastIndex int
}

func (na *nodeArray) next() (nodeName string, exhausted bool) {
	if len(na.nodes) == 0 {
		klog.Error("The nodeArray is empty. It should have been deleted from NodeTree.")
		return "", false
	}
	if na.lastIndex >= len(na.nodes) {
		return "", true
	}
	nodeName = na.nodes[na.lastIndex]
	na.lastIndex++
	return nodeName, false
}

// newNodeTree creates a NodeTree from nodes.
func newNodeTree(nodes []*v1.Node) *nodeTree {
	nt := &nodeTree{
		tree: make(map[string]*nodeArray),
	}
	for _, n := range nodes {
		nt.addNode(n)
	}
	return nt
}

// addNode adds a node and its corresponding zone to the tree. If the zone already exists, the node
// is added to the array of nodes in that zone.
func (nt *nodeTree) addNode(n *v1.Node) {
	zone := utilnode.GetZoneKey(n)
	if na, ok := nt.tree[zone]; ok {
		for _, nodeName := range na.nodes {
			if nodeName == n.Name {
				klog.Warningf("node %q already exist in the NodeTree", n.Name)
				return
			}
		}
		na.nodes = append(na.nodes, n.Name)
	} else {
		nt.zones = append(nt.zones, zone)
		nt.tree[zone] = &nodeArray{nodes: []string{n.Name}, lastIndex: 0}
	}
	klog.V(2).Infof("Added node %q in group %q to NodeTree", n.Name, zone)
	nt.numNodes++
}

// removeNode removes a node from the NodeTree.
func (nt *nodeTree) removeNode(n *v1.Node) error {
	zone := utilnode.GetZoneKey(n)
	if na, ok := nt.tree[zone]; ok {
		for i, nodeName := range na.nodes {
			if nodeName == n.Name {
				na.nodes = append(na.nodes[:i], na.nodes[i+1:]...)
				if len(na.nodes) == 0 {
					nt.removeZone(zone)
				}
				klog.V(2).Infof("Removed node %q in group %q from NodeTree", n.Name, zone)
				nt.numNodes--
				return nil
			}
		}
	}
	klog.Errorf("Node %q in group %q was not found", n.Name, zone)
	return fmt.Errorf("node %q in group %q was not found", n.Name, zone)
}

// removeZone removes a zone from tree.
// This function must be called while writer locks are hold.
func (nt *nodeTree) removeZone(zone string) {
	delete(nt.tree, zone)
	for i, z := range nt.zones {
		if z == zone {
			nt.zones = append(nt.zones[:i], nt.zones[i+1:]...)
			return
		}
	}
}

// updateNode updates a node in the NodeTree.
func (nt *nodeTree) updateNode(old, new *v1.Node) {
	var oldZone string
	if old != nil {
		oldZone = utilnode.GetZoneKey(old)
	}
	newZone := utilnode.GetZoneKey(new)
	// If the zone ID of the node has not changed, we don't need to do anything. Name of the node
	// cannot be changed in an update.
	if oldZone == newZone {
		return
	}
	nt.removeNode(old) // No error checking. We ignore whether the old node exists or not.
	nt.addNode(new)
}

func (nt *nodeTree) resetExhausted() {
	// dfy: 重置，用于遍历 zone 下的 nodes 集合（就是不同topology key 对应的 所有 nodes）
	for _, na := range nt.tree {
		na.lastIndex = 0
	}
	// dfy: 重置，用于遍历 zones 集合（就是 topology key集合）
	nt.zoneIndex = 0
}

// next returns the name of the next node. NodeTree iterates over zones and in each zone iterates
// over nodes in a round robin fashion.
func (nt *nodeTree) next() string {
	if len(nt.zones) == 0 {
		return ""
	}
	numExhaustedZones := 0
	for {
		if nt.zoneIndex >= len(nt.zones) {
			nt.zoneIndex = 0
		}
		// dfy: zones 应该是 topology key 集合，这里是取出一个 topology key
		zone := nt.zones[nt.zoneIndex]
		nt.zoneIndex++
		// We do not check the exhausted zones before calling next() on the zone. This ensures
		// that if more nodes are added to a zone after it is exhausted, we iterate over the new nodes.
		// dfy：从该 topology key 对应的 node 集合中，逐个取出 pod
		nodeName, exhausted := nt.tree[zone].next()
		if exhausted {
			// dfy: 当前 zone 已取完，取下一个 zone
			numExhaustedZones++
			// dfy: 所有 zone 都取完
			if numExhaustedZones >= len(nt.zones) { // all zones are exhausted. we should reset.
				nt.resetExhausted()
			}
		} else {
			// dfy: 返回此次 取出的 nodename
			return nodeName
		}
	}
}
