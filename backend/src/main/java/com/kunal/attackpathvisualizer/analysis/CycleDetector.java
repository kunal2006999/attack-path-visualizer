package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphNode;

import java.util.*;

public class CycleDetector {
    private final AttackGraph graph;
    private final DFSAnalyzer dfsAnalyzer;

    public CycleDetector(AttackGraph graph) {
        this.graph = graph;
        this.dfsAnalyzer = new DFSAnalyzer(graph);
    }

    public boolean hasCycle() {
        Deque<DFSFrame> stack = new ArrayDeque<>();
        Set<GraphNode> visited = new HashSet<>();
        Set<GraphNode> currentPath = new HashSet<>();

        for(GraphNode node: graph.getNodes()) {
            if (!visited.contains(node)) {
                stack.addLast(new DFSFrame(node, false));
                while(!stack.isEmpty()) {
                    DFSFrame frame = stack.removeLast();
                    if(frame.exiting) {
                        currentPath.remove(frame.node);
                        continue;
                    }
                    if(visited.contains(frame.node)) continue;
                    visited.add(frame.node);
                    currentPath.add(frame.node);
                    stack.addLast(new DFSFrame(frame.node, true));
                    for(GraphNode neighbour: graph.getNeighbors(frame.node.getId())) {
                        if(currentPath.contains(neighbour)) return true;
                        if(visited.contains(neighbour)) continue;
                        stack.addLast(new DFSFrame(neighbour, false));
                    }
                }
            }
        }

        return false;
    }
}
