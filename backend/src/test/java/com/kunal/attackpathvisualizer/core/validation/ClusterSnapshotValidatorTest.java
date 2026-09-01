package com.kunal.attackpathvisualizer.core.validation;

import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.PodSnapshot;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ClusterSnapshotValidatorTest {

    @Test
    void shouldAcceptValidSnapshot() {

        ClusterSnapshot snapshot = new ClusterSnapshot();

        snapshot.setClusterName("test-cluster");

        ClusterSnapshotValidator validator =
                new ClusterSnapshotValidator();

        assertDoesNotThrow(
                () -> validator.validate(snapshot)
        );
    }

    @Test
    void shouldRejectMissingClusterName() {

        ClusterSnapshot snapshot = new ClusterSnapshot();

        ClusterSnapshotValidator validator =
                new ClusterSnapshotValidator();

        assertThrows(
                IllegalArgumentException.class,
                () -> validator.validate(snapshot)
        );
    }

    @Test
    void shouldRejectResourceWithoutUid() {

        ClusterSnapshot snapshot = new ClusterSnapshot();

        snapshot.setClusterName("test-cluster");

        PodSnapshot pod = new PodSnapshot();

        pod.setName("backend-pod");
        pod.setNamespace("production");

        snapshot.setPods(List.of(pod));

        ClusterSnapshotValidator validator =
                new ClusterSnapshotValidator();

        assertThrows(
                IllegalArgumentException.class,
                () -> validator.validate(snapshot)
        );
    }

    @Test
    void shouldRejectDuplicateResourceUid() {

        ClusterSnapshot snapshot = new ClusterSnapshot();

        snapshot.setClusterName("test-cluster");

        PodSnapshot firstPod = new PodSnapshot();
        firstPod.setUid("pod-001");
        firstPod.setName("backend-pod");
        firstPod.setNamespace("production");

        PodSnapshot secondPod = new PodSnapshot();
        secondPod.setUid("pod-001");
        secondPod.setName("another-pod");
        secondPod.setNamespace("production");

        snapshot.setPods(
                List.of(firstPod, secondPod)
        );

        ClusterSnapshotValidator validator =
                new ClusterSnapshotValidator();

        assertThrows(
                IllegalArgumentException.class,
                () -> validator.validate(snapshot)
        );
    }
}