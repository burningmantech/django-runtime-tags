""" Provides safe version of eval.
    http://code.activestate.com/recipes/364469-safe-eval/

    Note that the input to this field is limited to trusted staff, so
    eval exploits are not so much a concern.
    This file contains the modifications mentioned in the comments for
    unary '-' and bool values.  It also prevents *any* value containing '__'.

    The article below discusses some of the evils of eval.  However, I've
    tested this module against these exploits and it just wraps them in
    quotes and does not execute the code.  As far as I can tell it's safe.
    http://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html
"""

# Here are the eval exploits from the article mentioned above:
# TestEvil_1 os.system('clear', {})
# TestEvil_3 eval("__import__('os').system('clear')", {'__builtins__':{}})
# TestEvil_2 eval("__import__('os').system('clear')", {})
# TestEvil_4 s = """ (lambda fc=(     lambda n: [         c for c in              ().__class__.__bases__[0].__subclasses__()              if c.__name__ == n         ][0]     ):     fc("function")(         fc("code")(             0,0,0,0,"KABOOM",(),(),(),"","",0,""         ),{}     )() )() """ eval(s, {'__builtins__':{}})

import compiler
from logging import getLogger

log = getLogger('django-runtime-tags')

class UnsafeSourceError(Exception):
    def __init__(self,error,descr = None,node = None):
        self.error = error
        self.descr = descr
        self.node = node
        self.lineno = getattr(node,"lineno",None)
        
    def __repr__(self):
        return "UnsafeSourceError Line %d.  %s: %s" % (
                self.lineno, self.error, self.descr)
    __str__ = __repr__    
           
class SafeEval(object):
    
    def visit(self, node,**kw):
        cls = node.__class__
        meth = getattr(self,'visit'+cls.__name__,self.default)
        return meth(node, **kw)
            
    def default(self, node, **kw):
        for child in node.getChildNodes():
            return self.visit(child, **kw)
            
    visitExpression = default
    
    def visitConst(self, node, **kw):
        return node.value

    def visitDict(self,node,**kw):
        return dict([(self.visit(k),self.visit(v)) for k,v in node.items])
        
    def visitTuple(self,node, **kw):
        return tuple(self.visit(i) for i in node.nodes)
        
    def visitList(self,node, **kw):
        return [self.visit(i) for i in node.nodes]

    def visitUnarySub(self, node, **kw):
            return -self.visit(node.getChildNodes()[0])

class SafeEvalWithErrors(SafeEval):

    def default(self, node, **kw):
        raise UnsafeSourceError("Unsupported source construct",
                                node.__class__,node)
            
    def visitName(self,node, **kw):
        if node.name == 'True':
            return True
        elif node.name == 'False':
            return False
        raise UnsafeSourceError("Strings must be quoted", 
                                 node.name, node)
                                 
    # Add more specific errors if desired
            

def safe_eval(source, fail_on_error=True, backstop_underscores=True):
    walker = fail_on_error and SafeEvalWithErrors() or SafeEval()

    # catches eval exploits -- already handled, this is a backstop
    if backstop_underscores:
        if '__' in source:
            raise SyntaxError("'__' is not allowed!")

    try:
        ast = compiler.parse(source,"eval")
    except SyntaxError, err:
        raise
    try:
        return walker.visit(ast)
    except UnsafeSourceError, err:
        raise
