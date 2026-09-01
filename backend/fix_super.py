import os
import glob

def fix_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    # Find the super() call
    # It looks like:
    #         super(
    #                 uid,
    #                 name,
    #                 namespace, # or null
    #                 ResourceType.SOMETHING,
    #                 labels,
    #                 annotations
    #         );
    
    if "super(" in content and "annotations\n        );" in content:
        content = content.replace("annotations\n        );", "annotations,\n                creationTimestamp\n        );")
    elif "super(" in content and "annotations\n\t\t);" in content:
        content = content.replace("annotations\n\t\t);", "annotations,\n\t\t\t\tcreationTimestamp\n\t\t);")
    
    with open(filepath, 'w') as f:
        f.write(content)

for filepath in glob.glob("src/main/java/com/kunal/attackpathvisualizer/core/model/*.java"):
    if not filepath.endswith("KubernetesResource.java") and not filepath.endswith("Cluster.java") and not filepath.endswith("RbacRule.java"):
        fix_file(filepath)
