package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.graph.GraphNode;

public class DFSFrame {
    GraphNode node;
    boolean exiting;

    DFSFrame(GraphNode node, boolean exiting) {
        this.node = node;
        this.exiting = exiting;
    }
}
