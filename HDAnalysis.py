# coding=gbk

import platform
import re
from pprint import pprint
from tabulate import tabulate

vectors = []
vector = {}
sub_tmp_list = []
process_cnts = {}
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
    filepath = "J:/OpenStack国家863项目/我的论文/CodeTE/"
    filename = "vectors-pyt-log.txt"
    #filename = "vectors-unit.txt"
else:
    filepath = "/k8slog/"
    filename = "vectors.txt"

def get_subject_string(subject):
    tmp = ""
    for sub_tmp in subject:
        tmp += sub_tmp + "\n"
    return tmp

def encode_subject(subject):
    res = "None"

    # String Print Algorithm (SP)
    # res = get_subject_string(subject)

    # Stack Level Count Algorithm (SLC)
    # res = str(subject.__len__())

    # Hash Digest Algorithm (HD)
    # tmp = ""
    # for sub_tmp in subject:
    #     tmp += sub_tmp + "\n"
    # res = str(hash(tmp))

    # Code Line Backtracking Algorithm (CLB)
    tmp = ""
    level = 5
    for i in range (0, min(subject.__len__(), level)):
        code_line = subject[i].split(", ")
        tmp += code_line[-1]
        if i != min(subject.__len__(), level) - 1:
            tmp += "-"
    res = tmp

    return res

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

    # print the human readable table:
    print tabulate(vectors, headers={"process": "Process", "no": "Freq", "path": "Path", "method": "Method",
                                     "encoded_subject": "ESubject", "subject": "Subject"})

    # print the policy
    # for vector in vectors:
    #     print vector["path"] + ", " + vector["method"]
    #     for sub_tmp in vector["subject"]:
    #         print sub_tmp
    #     print ""

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

def get_process(sub_tmp_list):
    for sub_tmp in sub_tmp_list:
        if sub_tmp.find("/pkg/apiserver") != -1:
            return "kube-apiserver"
        elif sub_tmp.find("/pkg/master") != -1:
            return "kube-controller-manager"
        elif sub_tmp.find("/ipallocator") != -1 or sub_tmp.find("/portallocator") != -1:
            return "kube-scheduler"

    if sub_tmp_list[0].find("/test") != -1:
        return "TEST"
    if sub_tmp_list[0].find("/test") != -1:
        return "TEST"

    for sub_tmp in sub_tmp_list:
        if sub_tmp.find("/pkg/util/wait") != -1:
            return "util"
        elif sub_tmp.find("/pkg/registry/generic") != -1:
            return "generic"
        elif sub_tmp.find(".etcdWatch") != -1 or sub_tmp.find(".etcdGetInitialWatchState") != -1:
            return "etcdWatch"

    return "None"

##################################################################################################
j = 0
for line in open(filepath + filename):
    if line.startswith("/"):
        vector.clear()
        path, method = line.strip().split(",")
        # vector["no"] = str(i)
        vector["no"] = 1

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
        # removed some items.
        # if sub_tmp_list[0].startswith("/test/"):
        #     j += 1
        #     continue
        vector['subject'] = sub_tmp_list
        vector['encoded_subject'] = encode_subject(sub_tmp_list)

        # get the "process"
        vector["process"] = get_process(sub_tmp_list)
        if not process_cnts.has_key(vector["process"]):
            process_cnts[vector["process"]] = 0
        process_cnts[vector["process"]] += 1

        # only show none "process" ones
        # if vector["process"] != "None":
        #    continue

        vectors.append(vector.copy())
        i += 1
        # print line,

vector_size_original = len(vectors) + j


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
                vectors[i - 1]["no"] += 1
                del vectors[i]
    else:
        i += 1

print_table()

vector_size = len(vectors)

print ""
print "Original size of vectors:", vector_size_original
print "Filtered size of vectors:", vector_size

freq_size = 0
for vector in vectors:
    freq_size += vector["no"]
print "Total frequency of vectors:", freq_size

sum = 0.0
for vector in vectors:
    sum += vector["encoded_subject"].__len__() * vector["no"]
sum /= vector_size_original
print "Average Size of encoded subjects:", round(sum, 2)

tmp_set = set()
for vector in vectors:
    tmp_set.add(get_subject_string(vector["subject"]))
sub_category_cnt = tmp_set.__len__()

tmp_set = set()
for vector in vectors:
    tmp_set.add(vector["encoded_subject"])
esub_category_cnt = tmp_set.__len__()

print "New conflicts:", sub_category_cnt - esub_category_cnt

print "\nProcesses:"

pprint(process_cnts)
