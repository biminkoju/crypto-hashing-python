import project
#hello this is the final testcase i am ever writing for cs50 python
def test_MD5():
    assert project.MD5("hello")=="4348162501f64525c6ee452501a14525"
    assert project.MD5("this")=="4ec890249774c0245c6dc0248c1fc024"
    assert project.MD5("is")=="ddf7382854a46928199d692807576928"
def test_SHA_256():
    assert project.SHA_256("the")=="4858f3785fa86f9c5e2f48e7060040fed3a37aa083464f4458db25b51e3757ad"
    assert project.SHA_256("final")=="e3aa97c42d51bc7f9b47ab9562b6be56eabb1069da2cada1d8d24666f8b116fe"
    assert project.SHA_256("testcase")=="02f86a49915e713f3d2e521bf97c35bf5d0183ba7c75dc9379d2deb426befd99"
def test_SHA0():
    assert project.SHA1("i")=="042dc4512fa3d391c5170cf3aa61e6a638f84342"
    assert project.SHA1("am")=="96e8155732e8324ae26f64d4516eb6fe696ac84f"
    assert project.SHA1("writing")=="1935d7b6e1cdaa0cb2a12b33ef6db0f1f938bf83"
