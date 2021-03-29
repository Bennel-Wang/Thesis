import json
def parseJson():
    #initialization
    with open('/media/sf_Sharefolder/dataset/DARPA2000-LLS_DDOS_2.0.2/inside2.csv', 'r') as f:
        data = list(json.load(f))
        for l in data:
            print(l['_source']['layers']['frame']['frame.coloring_rule.name'])

        #if len(result) > 0:
        #    name = ['Protocol', 'Time','Info']
        #    data = pd.DataFrame(columns=name, data=result)
        #    data.to_csv('/home/jin/Documents/Generated Data/Multi-step/'+ str(file))
        #    print('Multi-step grouping done')

if __name__ == '__main__':
    parseJson()
