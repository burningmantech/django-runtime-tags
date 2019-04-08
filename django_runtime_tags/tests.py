#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
This file tests the safe_eval module.  See this article for more info.
http://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html
"""
import os
import json
import unittest
from .safe_eval import safe_eval, UnsafeSourceError

# Safe
BooleanType = True, 'True'
DictionaryType = { 'red':256, 'green':256, 'blue':256 }, "{ 'red':256, 'green':256, 'blue':256 }"
FloatType = 1.618, '1.618'
IntType = 100, '100'
ListType = [1,2,3,4], '[1,2,3,4]'
LongType = 999999999, '999999999L'
StringType = 'Testing', "'Testing'"
TupleType = (1,2,3,4), '(1,2,3,4)'
UnicodeType = 'Testing', "u'Testing'"
NonASCIIUnicodeType = 'Voilà', "u'Voilà'"

# Unsafe
LambdaType = lambda x: x**2, 'lambda x: x**2'

# Evil
TestEvil_1 = 'evil1', "os.system('clear', {})"
TestEvil_2 = 'evil3', "eval(\"__import__('os').system('clear')\", {})"
TestEvil_3 = 'evil2', "eval(\"__import__('os').system('clear')\", {'__builtins__':{}})"
TestEvil_4 = 'evil4', '""" (lambda fc=(     lambda n: [         c for c in              ().__class__.__bases__[0].__subclasses__()              if c.__name__ == n         ][0]     ):     fc("function")(         fc("code")(             0,0,0,0,"KABOOM",(),(),(),"","",0,""         ),{}     )() )() """ eval(s, {\'__builtins__\':{}})'


safe_python_types = [
    BooleanType,
    DictionaryType,
    FloatType,
    IntType,
    ListType,
    LongType,
    StringType,
    TupleType,
    UnicodeType,
    NonASCIIUnicodeType,
]
unsafe_python_types = [
    LambdaType,
]
evil_python_spells = [
    TestEvil_1,
    TestEvil_2,
    TestEvil_3,
]
evil_python_syntax_spells = [
    TestEvil_4,
]


# Define function so we can pass to assertRaises (Python 2.7)
# Here we also disable the "backstop" test in safe_eval() which
# throws an exception when it finds '__'.   Just for testing.
def _safe_eval(eval_string):
    return safe_eval(eval_string, backstop_underscores=False)

class SafeEvalTest(unittest.TestCase):

    def setUp(self):
        pass

    def test_safe_types(self):
        for obj, obj_str in safe_python_types:
            try:
                self.assertEqual(type(obj), type(safe_eval(obj_str)))
            except (UnsafeSourceError, SyntaxError):
                raise

    def test_unsafe_types(self):
        for obj, eval_str in unsafe_python_types:
            self.assertRaises(UnsafeSourceError, _safe_eval, eval_str)
    
    def test_evil_syntax_types(self):
        for obj, eval_str in evil_python_syntax_spells:
            self.assertRaises(SyntaxError, _safe_eval, eval_str)

    def test_evil_types(self):
        for obj, eval_str in evil_python_spells:
            self.assertRaises(UnsafeSourceError, _safe_eval, eval_str)


if __name__ == '__main__':
    unittest.main()

#path = 'fixtures/django_runtime_tags/test_data.json'
#test_file = '%s/%s' % (os.path.dirname(os.path.abspath(__file__)), path)
#with open(test_file) as f:
#    tag_data = f.read()
#tag_list = json.loads(tag_data)
##os.system('df -h')
#
#tags = []
#for tag in tag_list + evil_tags:
#    tags.append(tag['fields'])
#
