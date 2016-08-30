# coding=gbk

import platform
import re
from pprint import pprint
from tabulate import tabulate

vectors = []
vector = {}
sub_tmp_list = []
i = 0

uuid_pattern = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
regex_uuid = re.compile(uuid_pattern)

subject_pattern = "k8s.io/kubernetes/"
regex_subject = re.compile(subject_pattern)

num_pattern = "/([^/]*([0-9]|test|my|auth-|pv)[^/]*|a$|pi$|rc$|quotaed.*|patch.*|allocatable.*|client.*|selflink.*|xxx$|[^/]*-[^/]*)"
regex_num = re.compile(num_pattern)

num2_pattern = "/(%NAME%.*|secret/%NAME%)"
regex_num2 = re.compile(num2_pattern)


if platform.system() == "Windows":
    filepath = "J:/OpenStack国家863项目/我的论文/HardenDocker/"
    filename = "vectors-integration-pyt.txt"
    #filename = "vectors-unit.txt"
else:
    filepath = "/k8slog/"
    filename = "vectors.txt"

def encode_subject(subject):
    return "Encoded: "

def print_table():
    # print part of "vectors"
    # for i in range(0, 300):
    #     print vectors[i]

    # print the path of "vectors"
    # for vector in vectors:
    #     print vector["path"]

    # print "vectors"
    # for vector in vectors:
    # vector["no"] = 0
    # vector["no"] = len(vector["subject"])
    # print vector

    print tabulate(vectors, headers={"process": "Process", "path": "Path", "method": "Method",
                                     "encoded_subject": "Encoded Subject", "subject": "Subject"})

    # print "Delete" vectors
    # for vector in vectors:
    #     if vector["method"] == "Delete":
    #         print vector


    # print statistics about "path" and "method"
    # paths = set()
    # methods = set()
    # for vector in vectors:
    #     paths.add(vector["path"])
    #     methods.add(vector["method"])
    #
    # print len(paths)
    # pprint(paths)
    # print len(methods)
    # print methods

##################################################################################################
j = 0
for line in open(filepath + filename):
    if line.startswith("/"):
        vector.clear()
        path, method = line.strip().split(",")
        # vector["no"] = str(i)

        # formalize the path
        vector["path"] = regex_uuid.sub("%UUID%", path.strip())
        vector["path"] = regex_num.sub("/%NAME%", vector["path"])
        vector["path"] = regex_num2.sub("/%NAME%", vector["path"])

        vector["method"] = method.strip()

        sub_tmp_list = []
    elif not line.startswith("\n"):
        if len(sub_tmp_list) < 100:
            sub_tmp_list.append(regex_subject.sub("/", line.strip()))
    else:
        if sub_tmp_list[0].startswith("/test/"):
            j += 1
            continue
        vector['subject'] = sub_tmp_list
        #vector['encoded_subject'] = encode_subject(sub_tmp_list)

        # get the "process"
        vector["process"] = "None"
        for sub_tmp in sub_tmp_list:
            if sub_tmp.find("/pkg/apiserver") != -1:
                vector["process"] = "kube-apiserver"
                break;
            elif sub_tmp.find("/pkg/master") != -1:
                vector["process"] = "kube-controller-manager"
                break;

        # only show none "process" ones
        # if vector["process"] != "None":
        #    continue

        vectors.append(vector.copy())
        i += 1
        # print line,

print "Original size of vectors:", len(vectors) + j

# sort the vectors based on "path"
vectors.sort(lambda x, y: cmp(x['subject'], y['subject']))
vectors = sorted(vectors, key=lambda x: x['subject'])
vectors.sort(lambda x, y: cmp(x['method'], y['method']))
vectors = sorted(vectors, key=lambda x: x['method'])
vectors.sort(lambda x, y: cmp(x['path'], y['path']))
vectors = sorted(vectors, key=lambda x: x['path'])

# remove the duplicated items in "vectors"
i = 1
while i < len(vectors):
    if (vectors[i]["path"] == vectors[i - 1]["path"] and
            vectors[i]["method"] == vectors[i - 1]["method"] and
            cmp(vectors[i]["subject"], vectors[i - 1]["subject"]) == 0):
                # vectors[i - 1]["no"] += (", " + vectors[i]["no"])
                del vectors[i]
    else:
        i += 1

print "Filtered size of vectors:", len(vectors)

print_table()
