#include "src/Common/DataInput/RandomDataInput.hpp"

int main()
{

    size_t clientSetSize = 1000;
    size_t serverSetSize = 1 << 24;
    size_t intersectionSetSize = 500;

    cout << "Test Random DataInput" << endl;
    cout << "Client Set Size: " << clientSetSize << endl;
    cout << "Server Set Size: " << serverSetSize << endl;
    cout << "Intersection Set Size: " << intersectionSetSize << endl;

    RandomDataInput RDI(serverSetSize, clientSetSize, intersectionSetSize, 1234567, 128);

    vector<biginteger> clientSet = RDI.getClientSet();
    vector<biginteger> serverSet = RDI.getServerSet();
    vector<biginteger> intersectionSet = RDI.getIntersectionSet();

    std::sort(clientSet.begin(), clientSet.end());
    std::sort(serverSet.begin(), serverSet.end());
    std::sort(intersectionSet.begin(), intersectionSet.end());


    set<biginteger> intersect;
    set_intersection(serverSet.begin(), serverSet.end(), clientSet.begin(), clientSet.end(),
                 std::inserter(intersect, intersect.begin()));
    set<biginteger> difference;
    std::set_difference(intersectionSet.begin(), intersectionSet.end(),
                    intersect.begin(), intersect.end(),
                    std::inserter(difference, difference.begin()));
    if(difference.empty() && intersect.size() == intersectionSet.size()) {
        cout << "Hooray, intersection equals" << endl;
    } else {
        cout << "Oh no, something went wrong" << endl;
        for(auto v : difference) {
            cout << "diff " << v << endl;
        }
    }

}