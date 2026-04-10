# Reconstructed from integrated Nuitka blob
# Module: uOpenGL.raw.GLU

a__qualname__
a__orig_bases__
a_fields_
aGLUnurbsObj
aGLUquadric
aGLUquadricObj
aGLUtesselator
aGLUtesselatorObj
aGLUtriangulatorObj
createBaseFunction
aPOINTER
ugluBeginCurve( POINTER(GLUnurbs)(nurb) ) -> None
T anurb
T agluBeginCurve
T adll
resultType
argTypes
doc
argNames
gluBeginCurve
ugluBeginPolygon( POINTER(GLUtesselator)(tess) ) -> None
T atess
T agluBeginPolygon
gluBeginPolygon
ugluBeginSurface( POINTER(GLUnurbs)(nurb) ) -> None
T agluBeginSurface
gluBeginSurface
ugluBeginTrim( POINTER(GLUnurbs)(nurb) ) -> None
T agluBeginTrim
gluBeginTrim
c_void_p
ugluBuild1DMipmapLevels( GLenum(target), GLint(internalFormat), GLsizei(width), GLenum(format), GLenum(type), GLint(level), GLint(base), GLint(max), c_void_p(data) ) -> GLint
T	atarget
internalFormat
width
format
type
level
base
max
data
T agluBuild1DMipmapLevels
gluBuild1DMipmapLevels
ugluBuild1DMipmaps( GLenum(target), GLint(internalFormat), GLsizei(width), GLenum(format), GLenum(type), c_void_p(data) ) -> GLint
T atarget
internalFormat
width
format
type
data
T agluBuild1DMipmaps
gluBuild1DMipmaps
ugluBuild2DMipmapLevels( GLenum(target), GLint(internalFormat), GLsizei(width), GLsizei(height), GLenum(format), GLenum(type), GLint(level), GLint(base), GLint(max), c_void_p(data) ) -> GLint
T
target
internalFormat
width
height
format
type
level
base
max
data
T agluBuild2DMipmapLevels
gluBuild2DMipmapLevels
ugluBuild2DMipmaps( GLenum(target), GLint(internalFormat), GLsizei(width), GLsizei(height), GLenum(format), GLenum(type), c_void_p(data) ) -> GLint
T atarget
internalFormat
width
height
format
type
data
T agluBuild2DMipmaps
gluBuild2DMipmaps
ugluBuild3DMipmapLevels( GLenum(target), GLint(internalFormat), GLsizei(width), GLsizei(height), GLsizei(depth), GLenum(format), GLenum(type), GLint(level), GLint(base), GLint(max), c_void_p(data) ) -> GLint
T atarget
internalFormat
width
height
depth
format
type
level
base
max
data
T agluBuild3DMipmapLevels
gluBuild3DMipmapLevels
ugluBuild3DMipmaps( GLenum(target), GLint(internalFormat), GLsizei(width), GLsizei(height), GLsizei(depth), GLenum(format), GLenum(type), c_void_p(data) ) -> GLint
T atarget
internalFormat
width
height
depth
format
type
data
T agluBuild3DMipmaps
gluBuild3DMipmaps
aGLubyteArray
ugluCheckExtension( arrays.GLubyteArray(extName), arrays.GLubyteArray(extString) ) -> GLboolean
T aextName
extString
T agluCheckExtension
gluCheckExtension
ugluCylinder( POINTER(GLUquadric)(quad), GLdouble(base), GLdouble(top), GLdouble(height), GLint(slices), GLint(stacks) ) -> None
T aquad
base
top
height
slices
stacks
T agluCylinder
gluCylinder
ugluDeleteNurbsRenderer( POINTER(GLUnurbs)(nurb) ) -> None
T agluDeleteNurbsRenderer
gluDeleteNurbsRenderer
ugluDeleteQuadric( POINTER(GLUquadric)(quad) ) -> None
T aquad
T agluDeleteQuadric
gluDeleteQuadric
ugluDeleteTess( POINTER(GLUtesselator)(tess) ) -> None
T agluDeleteTess
gluDeleteTess
ugluDisk( POINTER(GLUquadric)(quad), GLdouble(inner), GLdouble(outer), GLint(slices), GLint(loops) ) -> None
T aquad
inner
outer
slices
loops
T agluDisk
gluDisk
ugluEndCurve( POINTER(GLUnurbs)(nurb) ) -> None
T agluEndCurve
gluEndCurve
ugluEndPolygon( POINTER(GLUtesselator)(tess) ) -> None
T agluEndPolygon
gluEndPolygon
ugluEndSurface( POINTER(GLUnurbs)(nurb) ) -> None
T agluEndSurface
gluEndSurface
ugluEndTrim( POINTER(GLUnurbs)(nurb) ) -> None
T agluEndTrim
gluEndTrim
ugluErrorString( GLenum(error) ) -> POINTER(GLubyte)
T aerror
T agluErrorString
gluErrorString
aGLfloatArray
ugluGetNurbsProperty( POINTER(GLUnurbs)(nurb), GLenum(property), arrays.GLfloatArray(data) ) -> None
T anurb
property
data
T agluGetNurbsProperty
gluGetNurbsProperty
ugluGetString( GLenum(name) ) -> POINTER(GLubyte)
T aname
T agluGetString
gluGetString
aGLdoubleArray
ugluGetTessProperty( POINTER(GLUtesselator)(tess), GLenum(which), arrays.GLdoubleArray(data) ) -> None
T atess
which
data
T agluGetTessProperty
gluGetTessProperty
aGLintArray
ugluLoadSamplingMatrices( POINTER(GLUnurbs)(nurb), arrays.GLfloatArray(model), arrays.GLfloatArray(perspective), arrays.GLintArray(view) ) -> None
T anurb
model
perspective
view
T agluLoadSamplingMatrices
gluLoadSamplingMatrices
ugluLookAt( GLdouble(eyeX), GLdouble(eyeY), GLdouble(eyeZ), GLdouble(centerX), GLdouble(centerY), GLdouble(centerZ), GLdouble(upX), GLdouble(upY), GLdouble(upZ) ) -> None
T	aeyeX
eyeY
eyeZ
centerX
centerY
centerZ
upX
upY
upZ
T agluLookAt
gluLookAt
ugluNewNurbsRenderer(  ) -> POINTER(GLUnurbs)
T agluNewNurbsRenderer
gluNewNurbsRenderer
ugluNewQuadric(  ) -> POINTER(GLUquadric)
T agluNewQuadric
gluNewQuadric
ugluNewTess(  ) -> POINTER(GLUtesselator)
T agluNewTess
gluNewTess
ugluNextContour( POINTER(GLUtesselator)(tess), GLenum(type) ) -> None
T atess
type
T agluNextContour
gluNextContour
T na_GLUfuncptr
ugluNurbsCallback( POINTER(GLUnurbs)(nurb), GLenum(which), _GLUfuncptr(CallBackFunc) ) -> None
T anurb
which
aCallBackFunc
T agluNurbsCallback
gluNurbsCallback
ugluNurbsCallbackData( POINTER(GLUnurbs)(nurb), POINTER(GLvoid)(userData) ) -> None
T anurb
userData
T agluNurbsCallbackData
gluNurbsCallbackData
ugluNurbsCallbackDataEXT( POINTER(GLUnurbs)(nurb), POINTER(GLvoid)(userData) ) -> None
T agluNurbsCallbackDataEXT
gluNurbsCallbackDataEXT
ugluNurbsCurve( POINTER(GLUnurbs)(nurb), GLint(knotCount), arrays.GLfloatArray(knots), GLint(stride), arrays.GLfloatArray(control), GLint(order), GLenum(type) ) -> None
T anurb
knotCount
knots
stride
control
order
type
T agluNurbsCurve
gluNurbsCurve
ugluNurbsProperty( POINTER(GLUnurbs)(nurb), GLenum(property), GLfloat(value) ) -> None
T anurb
property
value
T agluNurbsProperty
gluNurbsProperty
ugluNurbsSurface( POINTER(GLUnurbs)(nurb), GLint(sKnotCount), arrays.GLfloatArray(sKnots), GLint(tKnotCount), arrays.GLfloatArray(tKnots), GLint(sStride), GLint(tStride), arrays.GLfloatArray(control), GLint(sOrder), GLint(tOrder), GLenum(type) ) -> None
T anurb
sKnotCount
sKnots
tKnotCount
tKnots
sStride
tStride
control
sOrder
tOrder
type
T agluNurbsSurface
gluNurbsSurface
ugluOrtho2D( GLdouble(left), GLdouble(right), GLdouble(bottom), GLdouble(top) ) -> None
T aleft
right
bottom
top
T agluOrtho2D
gluOrtho2D
ugluPartialDisk( POINTER(GLUquadric)(quad), GLdouble(inner), GLdouble(outer), GLint(slices), GLint(loops), GLdouble(start), GLdouble(sweep) ) -> None
T aquad
inner
outer
slices
loops
start
sweep
T agluPartialDisk
gluPartialDisk
ugluPerspective( GLdouble(fovy), GLdouble(aspect), GLdouble(zNear), GLdouble(zFar) ) -> None
T afovy
aspect
zNear
zFar
T agluPerspective
gluPerspective
ugluPickMatrix( GLdouble(x), GLdouble(y), GLdouble(delX), GLdouble(delY), arrays.GLintArray(viewport) ) -> None
T wxwyadelX
delY
viewport
T agluPickMatrix
gluPickMatrix
ugluProject( GLdouble(objX), GLdouble(objY), GLdouble(objZ), arrays.GLdoubleArray(model), arrays.GLdoubleArray(proj), arrays.GLintArray(view), arrays.GLdoubleArray(winX), arrays.GLdoubleArray(winY), arrays.GLdoubleArray(winZ) ) -> GLint
T	aobjX
objY
objZ
model
proj
view
winX
winY
winZ
T agluProject
gluProject
ugluPwlCurve( POINTER(GLUnurbs)(nurb), GLint(count), arrays.GLfloatArray(data), GLint(stride), GLenum(type) ) -> None
T anurb
count
data
stride
type
T agluPwlCurve
gluPwlCurve
ugluQuadricCallback( POINTER(GLUquadric)(quad), GLenum(which), _GLUfuncptr(CallBackFunc) ) -> None
T aquad
which
aCallBackFunc
T agluQuadricCallback
gluQuadricCallback
ugluQuadricDrawStyle( POINTER(GLUquadric)(quad), GLenum(draw) ) -> None
T aquad
draw
T agluQuadricDrawStyle
gluQuadricDrawStyle
ugluQuadricNormals( POINTER(GLUquadric)(quad), GLenum(normal) ) -> None
T aquad
normal
T agluQuadricNormals
gluQuadricNormals
ugluQuadricOrientation( POINTER(GLUquadric)(quad), GLenum(orientation) ) -> None
T aquad
orientation
T agluQuadricOrientation
gluQuadricOrientation
ugluQuadricTexture( POINTER(GLUquadric)(quad), GLboolean(texture) ) -> None
T aquad
texture
T agluQuadricTexture
gluQuadricTexture
ugluScaleImage( GLenum(format), GLsizei(wIn), GLsizei(hIn), GLenum(typeIn), c_void_p(dataIn), GLsizei(wOut), GLsizei(hOut), GLenum(typeOut), POINTER(GLvoid)(dataOut) ) -> GLint
T	aformat
wIn
hIn
typeIn
dataIn
wOut
hOut
typeOut
dataOut
T agluScaleImage
gluScaleImage
ugluSphere( POINTER(GLUquadric)(quad), GLdouble(radius), GLint(slices), GLint(stacks) ) -> None
T aquad
radius
slices
stacks
T agluSphere
gluSphere
ugluTessBeginContour( POINTER(GLUtesselator)(tess) ) -> None
T agluTessBeginContour
gluTessBeginContour
ugluTessBeginPolygon( POINTER(GLUtesselator)(tess), POINTER(GLvoid)(data) ) -> None
T atess
data
T agluTessBeginPolygon
gluTessBeginPolygon
ugluTessCallback( POINTER(GLUtesselator)(tess), GLenum(which), _GLUfuncptr(CallBackFunc) ) -> None
T atess
which
aCallBackFunc
T agluTessCallback
gluTessCallback
ugluTessEndContour( POINTER(GLUtesselator)(tess) ) -> None
T agluTessEndContour
gluTessEndContour
ugluTessEndPolygon( POINTER(GLUtesselator)(tess) ) -> None
T agluTessEndPolygon
gluTessEndPolygon
ugluTessNormal( POINTER(GLUtesselator)(tess), GLdouble(valueX), GLdouble(valueY), GLdouble(valueZ) ) -> None
T atess
valueX
valueY
valueZ
T agluTessNormal
gluTessNormal
ugluTessProperty( POINTER(GLUtesselator)(tess), GLenum(which), GLdouble(data) ) -> None
T agluTessProperty
gluTessProperty
ugluTessVertex( POINTER(GLUtesselator)(tess), arrays.GLdoubleArray(location), POINTER(GLvoid)(data) ) -> None
T atess
location
data
T agluTessVertex
gluTessVertex
ugluUnProject( GLdouble(winX), GLdouble(winY), GLdouble(winZ), arrays.GLdoubleArray(model), arrays.GLdoubleArray(proj), arrays.GLintArray(view), arrays.GLdoubleArray(objX), arrays.GLdoubleArray(objY), arrays.GLdoubleArray(objZ) ) -> GLint
T	awinX
winY
winZ
model
proj
view
objX
objY
objZ
T agluUnProject
gluUnProject
ugluUnProject4( GLdouble(winX), GLdouble(winY), GLdouble(winZ), GLdouble(clipW), arrays.GLdoubleArray(model), arrays.GLdoubleArray(proj), arrays.GLintArray(view), GLdouble(nearVal), GLdouble(farVal), arrays.GLdoubleArray(objX), arrays.GLdoubleArray(objY), arrays.GLdoubleArray(objZ), arrays.GLdoubleArray(objW) ) -> GLint
TawinX
winY
winZ
clipW
model
proj
view
nearVal
farVal
objX
objY
objZ
objW
T agluUnProject4
gluUnProject4
L  aGLU_AUTO_LOAD_MATRIX
aGLU_BEGIN
aGLU_CCW
aGLU_CULLING
aGLU_CW
aGLU_DISPLAY_MODE
aGLU_DOMAIN_DISTANCE
aGLU_EDGE_FLAG
aGLU_END
aGLU_ERROR
aGLU_EXTENSIONS
aGLU_EXTERIOR
aGLU_FALSE
aGLU_FILL
aGLU_FLAT
aGLU_INCOMPATIBLE_GL_VERSION
aGLU_INSIDE
aGLU_INTERIOR
aGLU_INVALID_ENUM
aGLU_INVALID_OPERATION
aGLU_INVALID_VALUE
aGLU_LINE
aGLU_MAP1_TRIM_2
aGLU_MAP1_TRIM_3
aGLU_NONE
aGLU_NURBS_BEGIN
aGLU_NURBS_BEGIN_DATA
aGLU_NURBS_BEGIN_DATA_EXT
aGLU_NURBS_BEGIN_EXT
aGLU_NURBS_COLOR
aGLU_NURBS_COLOR_DATA
aGLU_NURBS_COLOR_DATA_EXT
aGLU_NURBS_COLOR_EXT
aGLU_NURBS_END
aGLU_NURBS_END_DATA
aGLU_NURBS_END_DATA_EXT
aGLU_NURBS_END_EXT
aGLU_NURBS_ERROR
aGLU_NURBS_ERROR1
aGLU_NURBS_ERROR10
aGLU_NURBS_ERROR11
aGLU_NURBS_ERROR12
aGLU_NURBS_ERROR13
aGLU_NURBS_ERROR14
aGLU_NURBS_ERROR15
aGLU_NURBS_ERROR16
aGLU_NURBS_ERROR17
aGLU_NURBS_ERROR18
aGLU_NURBS_ERROR19
aGLU_NURBS_ERROR2
aGLU_NURBS_ERROR20
aGLU_NURBS_ERROR21
aGLU_NURBS_ERROR22
aGLU_NURBS_ERROR23
aGLU_NURBS_ERROR24
aGLU_NURBS_ERROR25
aGLU_NURBS_ERROR26
aGLU_NURBS_ERROR27
aGLU_NURBS_ERROR28
aGLU_NURBS_ERROR29
aGLU_NURBS_ERROR3
aGLU_NURBS_ERROR30
aGLU_NURBS_ERROR31
aGLU_NURBS_ERROR32
aGLU_NURBS_ERROR33
aGLU_NURBS_ERROR34
aGLU_NURBS_ERROR35
aGLU_NURBS_ERROR36
aGLU_NURBS_ERROR37
aGLU_NURBS_ERROR4
aGLU_NURBS_ERROR5
aGLU_NURBS_ERROR6
aGLU_NURBS_ERROR7
aGLU_NURBS_ERROR8
aGLU_NURBS_ERROR9
aGLU_NURBS_MODE
aGLU_NURBS_MODE_EXT
aGLU_NURBS_NORMAL
aGLU_NURBS_NORMAL_DATA
aGLU_NURBS_NORMAL_DATA_EXT
aGLU_NURBS_NORMAL_EXT
aGLU_NURBS_RENDERER
aGLU_NURBS_RENDERER_EXT
aGLU_NURBS_TESSELLATOR
aGLU_NURBS_TESSELLATOR_EXT
aGLU_NURBS_TEXTURE_COORD
aGLU_NURBS_TEXTURE_COORD_DATA
aGLU_NURBS_TEX_COORD_DATA_EXT
aGLU_NURBS_TEX_COORD_EXT
aGLU_NURBS_VERTEX
aGLU_NURBS_VERTEX_DATA
aGLU_NURBS_VERTEX_DATA_EXT
aGLU_NURBS_VERTEX_EXT
aGLU_OBJECT_PARAMETRIC_ERROR
aGLU_OBJECT_PARAMETRIC_ERROR_EXT
aGLU_OBJECT_PATH_LENGTH
aGLU_OBJECT_PATH_LENGTH_EXT
aGLU_OUTLINE_PATCH
aGLU_OUTLINE_POLYGON
aGLU_OUTSIDE
aGLU_OUT_OF_MEMORY
aGLU_PARAMETRIC_ERROR
aGLU_PARAMETRIC_TOLERANCE
aGLU_PATH_LENGTH
aGLU_POINT
aGLU_SAMPLING_METHOD
aGLU_SAMPLING_TOLERANCE
aGLU_SILHOUETTE
aGLU_SMOOTH
aGLU_TESS_BEGIN
aGLU_TESS_BEGIN_DATA
aGLU_TESS_BOUNDARY_ONLY
aGLU_TESS_COMBINE
aGLU_TESS_COMBINE_DATA
aGLU_TESS_COORD_TOO_LARGE
aGLU_TESS_EDGE_FLAG
aGLU_TESS_EDGE_FLAG_DATA
aGLU_TESS_END
aGLU_TESS_END_DATA
aGLU_TESS_ERROR
aGLU_TESS_ERROR1
aGLU_TESS_ERROR2
aGLU_TESS_ERROR3
aGLU_TESS_ERROR4
aGLU_TESS_ERROR5
aGLU_TESS_ERROR6
aGLU_TESS_ERROR7
aGLU_TESS_ERROR8
aGLU_TESS_ERROR_DATA
aGLU_TESS_MAX_COORD
aGLU_TESS_MISSING_BEGIN_CONTOUR
aGLU_TESS_MISSING_BEGIN_POLYGON
aGLU_TESS_MISSING_END_CONTOUR
aGLU_TESS_MISSING_END_POLYGON
aGLU_TESS_NEED_COMBINE_CALLBACK
aGLU_TESS_TOLERANCE
aGLU_TESS_VERTEX
aGLU_TESS_VERTEX_DATA
aGLU_TESS_WINDING_ABS_GEQ_TWO
aGLU_TESS_WINDING_NEGATIVE
aGLU_TESS_WINDING_NONZERO
aGLU_TESS_WINDING_ODD
aGLU_TESS_WINDING_POSITIVE
aGLU_TESS_WINDING_RULE
aGLU_TRUE
aGLU_UNKNOWN
aGLU_U_STEP
aGLU_VERSION
aGLU_VERSION_1_1
aGLU_VERSION_1_2
aGLU_VERSION_1_3
aGLU_VERTEX
aGLU_V_STEP
aGLUnurbs
aGLUnurbsObj
aGLUquadric
aGLUquadricObj
aGLUtesselator
aGLUtesselatorObj
aGLUtriangulatorObj
aGLboolean
aGLdouble
aGLenum
aGLfloat
aGLint
aGLsizei
aGLubyte
aGLvoid
a_GLUfuncptr
gluBeginCurve
gluBeginPolygon
gluBeginSurface
gluBeginTrim
gluBuild1DMipmapLevels
gluBuild1DMipmaps
gluBuild2DMipmapLevels
gluBuild2DMipmaps
gluBuild3DMipmapLevels
gluBuild3DMipmaps
gluCheckExtension
gluCylinder
gluDeleteNurbsRenderer
gluDeleteQuadric
gluDeleteTess
gluDisk
gluEndCurve
gluEndPolygon
gluEndSurface
gluEndTrim
gluErrorString
gluGetNurbsProperty
gluGetString
gluGetTessProperty
gluLoadSamplingMatrices
gluLookAt
gluNewNurbsRenderer
gluNewQuadric
gluNewTess
gluNextContour
gluNurbsCallback
gluNurbsCallbackData
gluNurbsCallbackDataEXT
gluNurbsCurve
gluNurbsProperty
gluNurbsSurface
gluOrtho2D
gluPartialDisk
gluPerspective
gluPickMatrix
gluProject
gluPwlCurve
gluQuadricCallback
gluQuadricDrawStyle
gluQuadricNormals
gluQuadricOrientation
gluQuadricTexture
gluScaleImage
gluSphere
gluTessBeginContour
gluTessBeginPolygon
gluTessCallback
gluTessEndContour
gluTessEndPolygon
gluTessNormal
gluTessProperty
gluTessVertex
gluUnProject
gluUnProject4
a__all__
uOpenGL\raw\GLU\__init__.py
u<module OpenGL.raw.GLU>

.OpenGL.raw.GLU.constants
'
J a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
aOpenGL
T aplatform
arrays
l
platform
arrays
uOpenGL.constant
T aConstant
aConstant
uOpenGL.raw.GL
T a_types
a_types
aGL_types
aGLvoid
T aGLU_AUTO_LOAD_MATRIX
l   aGLU_AUTO_LOAD_MATRIX
T aGLU_BEGIN
l   aGLU_BEGIN
T aGLU_CCW
l   aGLU_CCW
T aGLU_CULLING
l   aGLU_CULLING
T aGLU_CW
l   aGLU_CW
T aGLU_DISPLAY_MODE
l   aGLU_DISPLAY_MODE
T aGLU_DOMAIN_DISTANCE
l   aGLU_DOMAIN_DISTANCE
T aGLU_EDGE_FLAG
l   aGLU_EDGE_FLAG
T aGLU_END
l   aGLU_END
T aGLU_ERROR
l   aGLU_ERROR
T aGLU_EXTENSIONS
l   aGLU_EXTENSIONS
T aGLU_EXTERIOR
l   aGLU_EXTERIOR
T aGLU_FALSE
l
aGLU_FALSE
T aGLU_FILL
l   aGLU_FILL
T aGLU_FLAT
l   aGLU_FLAT
T aGLU_INCOMPATIBLE_GL_VERSION
l   aGLU_INCOMPATIBLE_GL_VERSION
T aGLU_INSIDE
l   aGLU_INSIDE
T aGLU_INTERIOR
l   aGLU_INTERIOR
T aGLU_INVALID_ENUM
l   aGLU_INVALID_ENUM
T aGLU_INVALID_OPERATION
l   aGLU_INVALID_OPERATION
T aGLU_INVALID_VALUE
l   aGLU_INVALID_VALUE
T aGLU_LINE
l   aGLU_LINE
T aGLU_MAP1_TRIM_2
l   aGLU_MAP1_TRIM_2
T aGLU_MAP1_TRIM_3
l   aGLU_MAP1_TRIM_3
T aGLU_NONE
l   aGLU_NONE
T aGLU_NURBS_BEGIN
l   aGLU_NURBS_BEGIN
T aGLU_NURBS_BEGIN_DATA
l   aGLU_NURBS_BEGIN_DATA
T aGLU_NURBS_BEGIN_DATA_EXT
l   aGLU_NURBS_BEGIN_DATA_EXT
T aGLU_NURBS_BEGIN_EXT
l   aGLU_NURBS_BEGIN_EXT
T aGLU_NURBS_COLOR
l   aGLU_NURBS_COLOR
T aGLU_NURBS_COLOR_DATA
l   aGLU_NURBS_COLOR_DATA
T aGLU_NURBS_COLOR_DATA_EXT
l   aGLU_NURBS_COLOR_DATA_EXT
T aGLU_NURBS_COLOR_EXT
l   aGLU_NURBS_COLOR_EXT
T aGLU_NURBS_END
l   aGLU_NURBS_END
T aGLU_NURBS_END_DATA
l   aGLU_NURBS_END_DATA
T aGLU_NURBS_END_DATA_EXT
l   aGLU_NURBS_END_DATA_EXT
T aGLU_NURBS_END_EXT
l   aGLU_NURBS_END_EXT
T aGLU_NURBS_ERROR
l   aGLU_NURBS_ERROR
T aGLU_NURBS_ERROR1
l   aGLU_NURBS_ERROR1
T aGLU_NURBS_ERROR10
l   aGLU_NURBS_ERROR10
T aGLU_NURBS_ERROR11
l   aGLU_NURBS_ERROR11
T aGLU_NURBS_ERROR12
l   aGLU_NURBS_ERROR12
T aGLU_NURBS_ERROR13
l   aGLU_NURBS_ERROR13
T aGLU_NURBS_ERROR14
l   aGLU_NURBS_ERROR14
T aGLU_NURBS_ERROR15
l   aGLU_NURBS_ERROR15
T aGLU_NURBS_ERROR16
l   aGLU_NURBS_ERROR16
T aGLU_NURBS_ERROR17
l   aGLU_NURBS_ERROR17
T aGLU_NURBS_ERROR18
l   aGLU_NURBS_ERROR18
T aGLU_NURBS_ERROR19
l   aGLU_NURBS_ERROR19
T aGLU_NURBS_ERROR2
l   aGLU_NURBS_ERROR2
T aGLU_NURBS_ERROR20
l   aGLU_NURBS_ERROR20
T aGLU_NURBS_ERROR21
l   aGLU_NURBS_ERROR21
T aGLU_NURBS_ERROR22
l   aGLU_NURBS_ERROR22
T aGLU_NURBS_ERROR23
l   aGLU_NURBS_ERROR23
T aGLU_NURBS_ERROR24
l   aGLU_NURBS_ERROR24
T aGLU_NURBS_ERROR25
l   aGLU_NURBS_ERROR25
T aGLU_NURBS_ERROR26
l   aGLU_NURBS_ERROR26
T aGLU_NURBS_ERROR27
l   aGLU_NURBS_ERROR27
T aGLU_NURBS_ERROR28
l   aGLU_NURBS_ERROR28
T aGLU_NURBS_ERROR29
l   aGLU_NURBS_ERROR29
T aGLU_NURBS_ERROR3
l   aGLU_NURBS_ERROR3
T aGLU_NURBS_ERROR30
l   aGLU_NURBS_ERROR30
T aGLU_NURBS_ERROR31
l   aGLU_NURBS_ERROR31
T aGLU_NURBS_ERROR32
l   aGLU_NURBS_ERROR32
T aGLU_NURBS_ERROR33
l   aGLU_NURBS_ERROR33
T aGLU_NURBS_ERROR34
l   aGLU_NURBS_ERROR34
T aGLU_NURBS_ERROR35
l   aGLU_NURBS_ERROR35
T aGLU_NURBS_ERROR36
l   aGLU_NURBS_ERROR36
T aGLU_NURBS_ERROR37
l   aGLU_NURBS_ERROR37
T aGLU_NURBS_ERROR4
l   aGLU_NURBS_ERROR4
T aGLU_NURBS_ERROR5
l   aGLU_NURBS_ERROR5
T aGLU_NURBS_ERROR6
l   aGLU_NURBS_ERROR6
T aGLU_NURBS_ERROR7
l   aGLU_NURBS_ERROR7
T aGLU_NURBS_ERROR8
l   aGLU_NURBS_ERROR8
T aGLU_NURBS_ERROR9
l   aGLU_NURBS_ERROR9
T aGLU_NURBS_MODE
l   aGLU_NURBS_MODE
T aGLU_NURBS_MODE_EXT
l   aGLU_NURBS_MODE_EXT
T aGLU_NURBS_NORMAL
l   aGLU_NURBS_NORMAL
T aGLU_NURBS_NORMAL_DATA
l   aGLU_NURBS_NORMAL_DATA
T aGLU_NURBS_NORMAL_DATA_EXT
l   aGLU_NURBS_NORMAL_DATA_EXT
T aGLU_NURBS_NORMAL_EXT
l   aGLU_NURBS_NORMAL_EXT
T aGLU_NURBS_RENDERER
l   aGLU_NURBS_RENDERER
T aGLU_NURBS_RENDERER_EXT
l   aGLU_NURBS_RENDERER_EXT
T aGLU_NURBS_TESSELLATOR
l   aGLU_NURBS_TESSELLATOR
T aGLU_NURBS_TESSELLATOR_EXT
l   aGLU_NURBS_TESSELLATOR_EXT
T aGLU_NURBS_TEXTURE_COORD
l   aGLU_NURBS_TEXTURE_COORD
T aGLU_NURBS_TEXTURE_COORD_DATA
l   aGLU_NURBS_TEXTURE_COORD_DATA
T aGLU_NURBS_TEX_COORD_DATA_EXT
l   aGLU_NURBS_TEX_COORD_DATA_EXT
T aGLU_NURBS_TEX_COORD_EXT
l   aGLU_NURBS_TEX_COORD_EXT
T aGLU_NURBS_VERTEX
l   aGLU_NURBS_VERTEX
T aGLU_NURBS_VERTEX_DATA
l   aGLU_NURBS_VERTEX_DATA
T aGLU_NURBS_VERTEX_DATA_EXT
l   aGLU_NURBS_VERTEX_DATA_EXT
T aGLU_NURBS_VERTEX_EXT
l   aGLU_NURBS_VERTEX_EXT
T aGLU_OBJECT_PARAMETRIC_ERROR
l   aGLU_OBJECT_PARAMETRIC_ERROR
T aGLU_OBJECT_PARAMETRIC_ERROR_EXT
l   aGLU_OBJECT_PARAMETRIC_ERROR_EXT
T aGLU_OBJECT_PATH_LENGTH
l   aGLU_OBJECT_PATH_LENGTH
T aGLU_OBJECT_PATH_LENGTH_EXT
l   aGLU_OBJECT_PATH_LENGTH_EXT
T aGLU_OUTLINE_PATCH
l   aGLU_OUTLINE_PATCH
T aGLU_OUTLINE_POLYGON
l   aGLU_OUTLINE_POLYGON
T aGLU_OUTSIDE
l   aGLU_OUTSIDE
T aGLU_OUT_OF_MEMORY
l   aGLU_OUT_OF_MEMORY
T aGLU_PARAMETRIC_ERROR
l   aGLU_PARAMETRIC_ERROR
T aGLU_PARAMETRIC_TOLERANCE
l   aGLU_PARAMETRIC_TOLERANCE
T aGLU_PATH_LENGTH
l   aGLU_PATH_LENGTH
T aGLU_POINT
l   aGLU_POINT
T aGLU_SAMPLING_METHOD
l   aGLU_SAMPLING_METHOD
T aGLU_SAMPLING_TOLERANCE
l   aGLU_SAMPLING_TOLERANCE
T aGLU_SILHOUETTE
l   aGLU_SILHOUETTE
T aGLU_SMOOTH
l   aGLU_SMOOTH
T aGLU_TESS_BEGIN
l   aGLU_TESS_BEGIN
T aGLU_TESS_BEGIN_DATA
l   aGLU_TESS_BEGIN_DATA
T aGLU_TESS_BOUNDARY_ONLY
l   aGLU_TESS_BOUNDARY_ONLY
T aGLU_TESS_COMBINE
l   aGLU_TESS_COMBINE
T aGLU_TESS_COMBINE_DATA
l   aGLU_TESS_COMBINE_DATA
T aGLU_TESS_COORD_TOO_LARGE
l   aGLU_TESS_COORD_TOO_LARGE
T aGLU_TESS_EDGE_FLAG
l   aGLU_TESS_EDGE_FLAG
T aGLU_TESS_EDGE_FLAG_DATA
l   aGLU_TESS_EDGE_FLAG_DATA
T aGLU_TESS_END
l   aGLU_TESS_END
T aGLU_TESS_END_DATA
l   aGLU_TESS_END_DATA
T aGLU_TESS_ERROR
l   aGLU_TESS_ERROR
T aGLU_TESS_ERROR1
l   aGLU_TESS_ERROR1
T aGLU_TESS_ERROR2
l   aGLU_TESS_ERROR2
T aGLU_TESS_ERROR3
l   aGLU_TESS_ERROR3
T aGLU_TESS_ERROR4
l   aGLU_TESS_ERROR4
T aGLU_TESS_ERROR5
l   aGLU_TESS_ERROR5
T aGLU_TESS_ERROR6
l   aGLU_TESS_ERROR6
T aGLU_TESS_ERROR7
l   aGLU_TESS_ERROR7
T aGLU_TESS_ERROR8
l   aGLU_TESS_ERROR8
T aGLU_TESS_ERROR_DATA
l   aGLU_TESS_ERROR_DATA
T aGLU_TESS_MAX_COORD
f  P.5  _aGLU_TESS_MAX_COORD
T aGLU_TESS_MISSING_BEGIN_CONTOUR
l   aGLU_TESS_MISSING_BEGIN_CONTOUR
T aGLU_TESS_MISSING_BEGIN_POLYGON
l   aGLU_TESS_MISSING_BEGIN_POLYGON
T aGLU_TESS_MISSING_END_CONTOUR
l   aGLU_TESS_MISSING_END_CONTOUR
T aGLU_TESS_MISSING_END_POLYGON
l   aGLU_TESS_MISSING_END_POLYGON
T aGLU_TESS_NEED_COMBINE_CALLBACK
l   aGLU_TESS_NEED_COMBINE_CALLBACK
T aGLU_TESS_TOLERANCE
l   aGLU_TESS_TOLERANCE
T aGLU_TESS_VERTEX
l   aGLU_TESS_VERTEX
T aGLU_TESS_VERTEX_DATA
l   aGLU_TESS_VERTEX_DATA
T aGLU_TESS_WINDING_ABS_GEQ_TWO
l   aGLU_TESS_WINDING_ABS_GEQ_TWO
T aGLU_TESS_WINDING_NEGATIVE
l   aGLU_TESS_WINDING_NEGATIVE
T aGLU_TESS_WINDING_NONZERO
l   aGLU_TESS_WINDING_NONZERO
T aGLU_TESS_WINDING_ODD
l   aGLU_TESS_WINDING_ODD
T aGLU_TESS_WINDING_POSITIVE
l   aGLU_TESS_WINDING_POSITIVE
T aGLU_TESS_WINDING_RULE
l   aGLU_TESS_WINDING_RULE
T aGLU_TRUE
l aGLU_TRUE
T aGLU_UNKNOWN
l   aGLU_UNKNOWN
T aGLU_U_STEP
l   aGLU_U_STEP
T aGLU_VERSION
l   aGLU_VERSION
T aGLU_VERSION_1_1
l aGLU_VERSION_1_1
T aGLU_VERSION_1_2
l aGLU_VERSION_1_2
T aGLU_VERSION_1_3
l aGLU_VERSION_1_3
T aGLU_VERTEX
l   aGLU_VERTEX
T aGLU_V_STEP
l   aGLU_V_STEP
L  aGLU_AUTO_LOAD_MATRIX
aGLU_BEGIN
aGLU_CCW
aGLU_CULLING
aGLU_CW
aGLU_DISPLAY_MODE
aGLU_DOMAIN_DISTANCE
aGLU_EDGE_FLAG
aGLU_END
aGLU_ERROR
aGLU_EXTENSIONS
aGLU_EXTERIOR
aGLU_FALSE
aGLU_FILL
aGLU_FLAT
aGLU_INCOMPATIBLE_GL_VERSION
aGLU_INSIDE
aGLU_INTERIOR
aGLU_INVALID_ENUM
aGLU_INVALID_OPERATION
aGLU_INVALID_VALUE
aGLU_LINE
aGLU_MAP1_TRIM_2
aGLU_MAP1_TRIM_3
aGLU_NONE
aGLU_NURBS_BEGIN
aGLU_NURBS_BEGIN_DATA
aGLU_NURBS_BEGIN_DATA_EXT
aGLU_NURBS_BEGIN_EXT
aGLU_NURBS_COLOR
aGLU_NURBS_COLOR_DATA
aGLU_NURBS_COLOR_DATA_EXT
aGLU_NURBS_COLOR_EXT
aGLU_NURBS_END
aGLU_NURBS_END_DATA
aGLU_NURBS_END_DATA_EXT
aGLU_NURBS_END_EXT
aGLU_NURBS_ERROR
aGLU_NURBS_ERROR1
aGLU_NURBS_ERROR10
aGLU_NURBS_ERROR11
aGLU_NURBS_ERROR12
aGLU_NURBS_ERROR13
aGLU_NURBS_ERROR14
aGLU_NURBS_ERROR15
aGLU_NURBS_ERROR16
aGLU_NURBS_ERROR17
aGLU_NURBS_ERROR18
aGLU_NURBS_ERROR19
aGLU_NURBS_ERROR2
aGLU_NURBS_ERROR20
aGLU_NURBS_ERROR21
aGLU_NURBS_ERROR22
aGLU_NURBS_ERROR23
aGLU_NURBS_ERROR24
aGLU_NURBS_ERROR25
aGLU_NURBS_ERROR26
aGLU_NURBS_ERROR27
aGLU_NURBS_ERROR28
aGLU_NURBS_ERROR29
aGLU_NURBS_ERROR3
aGLU_NURBS_ERROR30
aGLU_NURBS_ERROR31
aGLU_NURBS_ERROR32
aGLU_NURBS_ERROR33
aGLU_NURBS_ERROR34
aGLU_NURBS_ERROR35
aGLU_NURBS_ERROR36
aGLU_NURBS_ERROR37
aGLU_NURBS_ERROR4
aGLU_NURBS_ERROR5
aGLU_NURBS_ERROR6
aGLU_NURBS_ERROR7
aGLU_NURBS_ERROR8
aGLU_NURBS_ERROR9
aGLU_NURBS_MODE
aGLU_NURBS_MODE_EXT
aGLU_NURBS_NORMAL
aGLU_NURBS_NORMAL_DATA
aGLU_NURBS_NORMAL_DATA_EXT
aGLU_NURBS_NORMAL_EXT
aGLU_NURBS_RENDERER
aGLU_NURBS_RENDERER_EXT
aGLU_NURBS_TESSELLATOR
aGLU_NURBS_TESSELLATOR_EXT
aGLU_NURBS_TEXTURE_COORD
aGLU_NURBS_TEXTURE_COORD_DATA
aGLU_NURBS_TEX_COORD_DATA_EXT
aGLU_NURBS_TEX_COORD_EXT
aGLU_NURBS_VERTEX
aGLU_NURBS_VERTEX_DATA
aGLU_NURBS_VERTEX_DATA_EXT
aGLU_NURBS_VERTEX_EXT
aGLU_OBJECT_PARAMETRIC_ERROR
aGLU_OBJECT_PARAMETRIC_ERROR_EXT
aGLU_OBJECT_PATH_LENGTH
aGLU_OBJECT_PATH_LENGTH_EXT
aGLU_OUTLINE_PATCH
aGLU_OUTLINE_POLYGON
aGLU_OUTSIDE
aGLU_OUT_OF_MEMORY
aGLU_PARAMETRIC_ERROR
aGLU_PARAMETRIC_TOLERANCE
aGLU_PATH_LENGTH
aGLU_POINT
aGLU_SAMPLING_METHOD
aGLU_SAMPLING_TOLERANCE
aGLU_SILHOUETTE
aGLU_SMOOTH
aGLU_TESS_BEGIN
aGLU_TESS_BEGIN_DATA
aGLU_TESS_BOUNDARY_ONLY
aGLU_TESS_COMBINE
aGLU_TESS_COMBINE_DATA
aGLU_TESS_COORD_TOO_LARGE
aGLU_TESS_EDGE_FLAG
aGLU_TESS_EDGE_FLAG_DATA
aGLU_TESS_END
aGLU_TESS_END_DATA
aGLU_TESS_ERROR
aGLU_TESS_ERROR1
aGLU_TESS_ERROR2
aGLU_TESS_ERROR3
aGLU_TESS_ERROR4
aGLU_TESS_ERROR5
aGLU_TESS_ERROR6
aGLU_TESS_ERROR7
aGLU_TESS_ERROR8
aGLU_TESS_ERROR_DATA
aGLU_TESS_MAX_COORD
aGLU_TESS_MISSING_BEGIN_CONTOUR
aGLU_TESS_MISSING_BEGIN_POLYGON
aGLU_TESS_MISSING_END_CONTOUR
aGLU_TESS_MISSING_END_POLYGON
aGLU_TESS_NEED_COMBINE_CALLBACK
aGLU_TESS_TOLERANCE
aGLU_TESS_VERTEX
aGLU_TESS_VERTEX_DATA
aGLU_TESS_WINDING_ABS_GEQ_TWO
aGLU_TESS_WINDING_NEGATIVE
aGLU_TESS_WINDING_NONZERO
aGLU_TESS_WINDING_ODD
aGLU_TESS_WINDING_POSITIVE
aGLU_TESS_WINDING_RULE
aGLU_TRUE
aGLU_UNKNOWN
aGLU_U_STEP
aGLU_VERSION
aGLU_VERSION_1_1
aGLU_VERSION_1_2
aGLU_VERSION_1_3
aGLU_VERTEX
aGLU_V_STEP
a__all__
uOpenGL\raw\GLU\constants.py
u<module OpenGL.raw.GLU.constants>

.OpenGL.raw.GLUT.annotations
N
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
uOpenGL.raw
T aGLUT
l
aGLUT
raw
aOpenGL
T aplatform
arrays
platform
arrays
uOpenGL.constant
T aConstant
aConstant
uOpenGL.raw.GL
T a_types
a_types
aGL_types
aGLvoid
c_char_p
aSTRING
a__all__
uOpenGL\raw\GLUT\annotations.py
u<module OpenGL.raw.GLUT.annotations>

.OpenGL.raw.GLUT
nE
isinstance
unicode
encode
T uutf-8
c_char_p
from_param
value
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_OpenGL
u\not_existing
uraw\GLUT
T aNUITKA_PACKAGE_OpenGL_raw
u\not_existing
aGLUT
T aNUITKA_PACKAGE_OpenGL_raw_GLUT
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
uOpenGL.raw.GLUT.constants
T w*l
uOpenGL._bytes
T aunicode
aOpenGL
T aplatform
arrays
platform
arrays
uOpenGL.constant
T aConstant
aConstant
uOpenGL.raw.GL
T a_types
a_types
aGL_types
aGLvoid
uOpenGL.raw.GL._types
T aGLint
aGLenum
aGLdouble
aGLfloat
aGLint
aGLenum
aGLdouble
aGLfloat
hasattr
aPLATFORM
aGLUT_CALLBACK_TYPE
aCALLBACK_FUNCTION_TYPE
functionTypeFor
a__prepare__
aSTRING
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
