# Reconstructed from integrated Nuitka blob
# Module: uOpenGL.raw.GLUT

a__qualname__
classmethod
uSTRING.from_param
a__orig_bases__
createBaseFunction
c_int
uglutAddMenuEntry( STRING(label), c_int(value) ) -> None
T alabel
value
T aglutAddMenuEntry
T adll
resultType
argTypes
doc
argNames
glutAddMenuEntry
uglutAddSubMenu( STRING(label), c_int(subMenu) ) -> None
T alabel
subMenu
T aglutAddSubMenu
glutAddSubMenu
uglutAttachMenu( c_int(button) ) -> None
T abutton
T aglutAttachMenu
glutAttachMenu
c_void_p
uglutBitmapCharacter( c_void_p(font), c_int(character) ) -> None
T afont
character
T aglutBitmapCharacter
glutBitmapCharacter
aPOINTER
c_ubyte
uglutBitmapLength( c_void_p(font), POINTER(c_ubyte)(string) ) -> c_int
T afont
string
T aglutBitmapLength
glutBitmapLength
uglutBitmapWidth( c_void_p(font), c_int(character) ) -> c_int
T aglutBitmapWidth
glutBitmapWidth
uglutButtonBoxFunc( FUNCTION_TYPE(None, c_int, c_int)(callback) ) -> None
T acallback
T aglutButtonBoxFunc
glutButtonBoxFunc
uglutChangeToMenuEntry( c_int(item), STRING(label), c_int(value) ) -> None
T aitem
label
value
T aglutChangeToMenuEntry
glutChangeToMenuEntry
uglutChangeToSubMenu( c_int(item), STRING(label), c_int(value) ) -> None
T aglutChangeToSubMenu
glutChangeToSubMenu
uglutCopyColormap( c_int(window) ) -> None
T awindow
T aglutCopyColormap
glutCopyColormap
uglutCreateMenu( FUNCTION_TYPE(c_int, c_int)(callback) ) -> c_int
T aglutCreateMenu
glutCreateMenu
uglutCreateSubWindow( c_int(window), c_int(x), c_int(y), c_int(width), c_int(height) ) -> c_int
T awindow
wxwyawidth
height
T aglutCreateSubWindow
glutCreateSubWindow
uglutCreateWindow( STRING(title) ) -> c_int
T atitle
T aglutCreateWindow
glutCreateWindow
uglutDestroyMenu( c_int(menu) ) -> None
T amenu
T aglutDestroyMenu
glutDestroyMenu
uglutDestroyWindow( c_int(window) ) -> None
T aglutDestroyWindow
glutDestroyWindow
uglutDetachMenu( c_int(button) ) -> None
T aglutDetachMenu
glutDetachMenu
uglutDeviceGet( GLenum(query) ) -> c_int
T aquery
T aglutDeviceGet
glutDeviceGet
uglutDialsFunc( FUNCTION_TYPE(None, c_int, c_int)(callback) ) -> None
T aglutDialsFunc
glutDialsFunc
T nuglutDisplayFunc( FUNCTION_TYPE(None)(callback) ) -> None
T aglutDisplayFunc
glutDisplayFunc
uglutEnterGameMode(  ) -> c_int
T aglutEnterGameMode
glutEnterGameMode
uglutEntryFunc( FUNCTION_TYPE(None, c_int)(callback) ) -> None
T aglutEntryFunc
glutEntryFunc
uglutEstablishOverlay(  ) -> None
T aglutEstablishOverlay
glutEstablishOverlay
uglutExtensionSupported( STRING(extension) ) -> c_int
T aextension
T aglutExtensionSupported
glutExtensionSupported
uglutForceJoystickFunc(  ) -> None
T aglutForceJoystickFunc
glutForceJoystickFunc
uglutFullScreen(  ) -> None
T aglutFullScreen
glutFullScreen
uglutGameModeGet( GLenum(query) ) -> c_int
T aglutGameModeGet
glutGameModeGet
uglutGameModeString( STRING(string) ) -> None
T astring
T aglutGameModeString
glutGameModeString
uglutGet( GLenum(query) ) -> c_int
T aglutGet
glutGet
uglutGetColor( c_int(color), c_int(component) ) -> GLfloat
T acolor
component
T aglutGetColor
glutGetColor
uglutGetMenu(  ) -> c_int
T aglutGetMenu
glutGetMenu
uglutGetModifiers(  ) -> c_int
T aglutGetModifiers
glutGetModifiers
uglutGetWindow(  ) -> c_int
T aglutGetWindow
glutGetWindow
uglutHideOverlay(  ) -> None
T aglutHideOverlay
glutHideOverlay
uglutHideWindow(  ) -> None
T aglutHideWindow
glutHideWindow
uglutIconifyWindow(  ) -> None
T aglutIconifyWindow
glutIconifyWindow
uglutIdleFunc( FUNCTION_TYPE(None)(callback) ) -> None
T aglutIdleFunc
glutIdleFunc
uglutIgnoreKeyRepeat( c_int(ignore) ) -> None
T aignore
T aglutIgnoreKeyRepeat
glutIgnoreKeyRepeat
uglutInit( POINTER(c_int)(pargc), POINTER(STRING)(argv) ) -> None
T apargc
argv
T aglutInit
glutInit
c_uint
uglutInitDisplayMode( c_uint(displayMode) ) -> None
T adisplayMode
T aglutInitDisplayMode
glutInitDisplayMode
uglutInitDisplayString( STRING(displayMode) ) -> None
T aglutInitDisplayString
glutInitDisplayString
uglutInitWindowPosition( c_int(x), c_int(y) ) -> None
T wxwyT aglutInitWindowPosition
glutInitWindowPosition
uglutInitWindowSize( c_int(width), c_int(height) ) -> None
T awidth
height
T aglutInitWindowSize
glutInitWindowSize
uglutJoystickFunc( FUNCTION_TYPE(None, c_uint, c_int, c_int, c_int)(callback), c_int(pollInterval) ) -> None
T acallback
pollInterval
T aglutJoystickFunc
glutJoystickFunc
uglutKeyboardFunc( FUNCTION_TYPE(None, c_ubyte, c_int, c_int)(callback) ) -> None
T aglutKeyboardFunc
glutKeyboardFunc
uglutKeyboardUpFunc( FUNCTION_TYPE(None, c_ubyte, c_int, c_int)(callback) ) -> None
T aglutKeyboardUpFunc
glutKeyboardUpFunc
uglutLayerGet( GLenum(query) ) -> c_int
T aglutLayerGet
glutLayerGet
uglutLeaveGameMode(  ) -> None
T aglutLeaveGameMode
glutLeaveGameMode
uglutMainLoop(  ) -> None
T aglutMainLoop
glutMainLoop
uglutMenuStateFunc( FUNCTION_TYPE(None, c_int)(callback) ) -> None
T aglutMenuStateFunc
glutMenuStateFunc
uglutMenuStatusFunc( FUNCTION_TYPE(None, c_int, c_int, c_int)(callback) ) -> None
T aglutMenuStatusFunc
glutMenuStatusFunc
uglutMotionFunc( FUNCTION_TYPE(None, c_int, c_int)(callback) ) -> None
T aglutMotionFunc
glutMotionFunc
uglutMouseFunc( FUNCTION_TYPE(None, c_int, c_int, c_int, c_int)(callback) ) -> None
T aglutMouseFunc
glutMouseFunc
uglutOverlayDisplayFunc( FUNCTION_TYPE(None)(callback) ) -> None
T aglutOverlayDisplayFunc
glutOverlayDisplayFunc
uglutPassiveMotionFunc( FUNCTION_TYPE(None, c_int, c_int)(callback) ) -> None
T aglutPassiveMotionFunc
glutPassiveMotionFunc
uglutPopWindow(  ) -> None
T aglutPopWindow
glutPopWindow
uglutPositionWindow( c_int(x), c_int(y) ) -> None
T aglutPositionWindow
glutPositionWindow
uglutPostOverlayRedisplay(  ) -> None
T aglutPostOverlayRedisplay
glutPostOverlayRedisplay
uglutPostRedisplay(  ) -> None
T aglutPostRedisplay
glutPostRedisplay
uglutPostWindowOverlayRedisplay( c_int(window) ) -> None
T aglutPostWindowOverlayRedisplay
glutPostWindowOverlayRedisplay
uglutPostWindowRedisplay( c_int(window) ) -> None
T aglutPostWindowRedisplay
glutPostWindowRedisplay
uglutPushWindow(  ) -> None
T aglutPushWindow
glutPushWindow
uglutRemoveMenuItem( c_int(item) ) -> None
T aitem
T aglutRemoveMenuItem
glutRemoveMenuItem
uglutRemoveOverlay(  ) -> None
T aglutRemoveOverlay
glutRemoveOverlay
uglutReportErrors(  ) -> None
T aglutReportErrors
glutReportErrors
uglutReshapeFunc( FUNCTION_TYPE(None, c_int, c_int)(callback) ) -> None
T aglutReshapeFunc
glutReshapeFunc
uglutReshapeWindow( c_int(width), c_int(height) ) -> None
T aglutReshapeWindow
glutReshapeWindow
uglutSetColor( c_int(color), GLfloat(red), GLfloat(green), GLfloat(blue) ) -> None
T acolor
red
green
blue
T aglutSetColor
glutSetColor
uglutSetCursor( c_int(cursor) ) -> None
T acursor
T aglutSetCursor
glutSetCursor
uglutSetIconTitle( STRING(title) ) -> None
T aglutSetIconTitle
glutSetIconTitle
uglutSetKeyRepeat( c_int(repeatMode) ) -> None
T arepeatMode
T aglutSetKeyRepeat
glutSetKeyRepeat
uglutSetMenu( c_int(menu) ) -> None
T aglutSetMenu
glutSetMenu
uglutSetWindow( c_int(window) ) -> None
T aglutSetWindow
glutSetWindow
uglutSetWindowTitle( STRING(title) ) -> None
T aglutSetWindowTitle
glutSetWindowTitle
uglutSetupVideoResizing(  ) -> None
T aglutSetupVideoResizing
glutSetupVideoResizing
uglutShowOverlay(  ) -> None
T aglutShowOverlay
glutShowOverlay
uglutShowWindow(  ) -> None
T aglutShowWindow
glutShowWindow
uglutSolidCone( GLdouble(base), GLdouble(height), GLint(slices), GLint(stacks) ) -> None
T abase
height
slices
stacks
T aglutSolidCone
glutSolidCone
uglutSolidCube( GLdouble(size) ) -> None
T asize
T aglutSolidCube
glutSolidCube
uglutSolidDodecahedron(  ) -> None
T aglutSolidDodecahedron
glutSolidDodecahedron
uglutSolidIcosahedron(  ) -> None
T aglutSolidIcosahedron
glutSolidIcosahedron
uglutSolidOctahedron(  ) -> None
T aglutSolidOctahedron
glutSolidOctahedron
uglutSolidSphere( GLdouble(radius), GLint(slices), GLint(stacks) ) -> None
T aradius
slices
stacks
T aglutSolidSphere
glutSolidSphere
uglutSolidTeapot( GLdouble(size) ) -> None
T aglutSolidTeapot
glutSolidTeapot
uglutSolidTetrahedron(  ) -> None
T aglutSolidTetrahedron
glutSolidTetrahedron
uglutSolidTorus( GLdouble(innerRadius), GLdouble(outerRadius), GLint(sides), GLint(rings) ) -> None
T ainnerRadius
outerRadius
sides
rings
T aglutSolidTorus
glutSolidTorus
uglutSpaceballButtonFunc( FUNCTION_TYPE(None, c_int, c_int)(callback) ) -> None
T aglutSpaceballButtonFunc
glutSpaceballButtonFunc
uglutSpaceballMotionFunc( FUNCTION_TYPE(None, c_int, c_int, c_int)(callback) ) -> None
T aglutSpaceballMotionFunc
glutSpaceballMotionFunc
uglutSpaceballRotateFunc( FUNCTION_TYPE(None, c_int, c_int, c_int)(callback) ) -> None
T aglutSpaceballRotateFunc
glutSpaceballRotateFunc
uglutSpecialFunc( FUNCTION_TYPE(None, c_int, c_int, c_int)(callback) ) -> None
T aglutSpecialFunc
glutSpecialFunc
uglutSpecialUpFunc( FUNCTION_TYPE(None, c_int, c_int, c_int)(callback) ) -> None
T aglutSpecialUpFunc
glutSpecialUpFunc
uglutStopVideoResizing(  ) -> None
T aglutStopVideoResizing
glutStopVideoResizing
uglutStrokeCharacter( c_void_p(font), c_int(character) ) -> None
T aglutStrokeCharacter
glutStrokeCharacter
uglutStrokeLength( c_void_p(font), POINTER(c_ubyte)(string) ) -> c_int
T aglutStrokeLength
glutStrokeLength
uglutStrokeWidth( c_void_p(font), c_int(character) ) -> c_int
T aglutStrokeWidth
glutStrokeWidth
uglutSwapBuffers(  ) -> None
T aglutSwapBuffers
glutSwapBuffers
uglutTabletButtonFunc( FUNCTION_TYPE(None, c_int, c_int, c_int, c_int)(callback) ) -> None
T aglutTabletButtonFunc
glutTabletButtonFunc
uglutTabletMotionFunc( FUNCTION_TYPE(None, c_int, c_int)(callback) ) -> None
T aglutTabletMotionFunc
glutTabletMotionFunc
uglutTimerFunc( c_uint(time), FUNCTION_TYPE(None, c_int)(callback), c_int(value) ) -> None
T atime
callback
value
T aglutTimerFunc
glutTimerFunc
uglutUseLayer( GLenum(layer) ) -> None
T alayer
T aglutUseLayer
glutUseLayer
uglutVideoPan( c_int(x), c_int(y), c_int(width), c_int(height) ) -> None
T wxwyawidth
height
T aglutVideoPan
glutVideoPan
uglutVideoResize( c_int(x), c_int(y), c_int(width), c_int(height) ) -> None
T aglutVideoResize
glutVideoResize
uglutVideoResizeGet( GLenum(query) ) -> c_int
T aglutVideoResizeGet
glutVideoResizeGet
uglutVisibilityFunc( FUNCTION_TYPE(None, c_int)(callback) ) -> None
T aglutVisibilityFunc
glutVisibilityFunc
uglutWarpPointer( c_int(x), c_int(y) ) -> None
T aglutWarpPointer
glutWarpPointer
uglutWindowStatusFunc( FUNCTION_TYPE(None, c_int)(callback) ) -> None
T aglutWindowStatusFunc
glutWindowStatusFunc
uglutWireCone( GLdouble(base), GLdouble(height), GLint(slices), GLint(stacks) ) -> None
T aglutWireCone
glutWireCone
uglutWireCube( GLdouble(size) ) -> None
T aglutWireCube
glutWireCube
uglutWireDodecahedron(  ) -> None
T aglutWireDodecahedron
glutWireDodecahedron
uglutWireIcosahedron(  ) -> None
T aglutWireIcosahedron
glutWireIcosahedron
uglutWireOctahedron(  ) -> None
T aglutWireOctahedron
glutWireOctahedron
uglutWireSphere( GLdouble(radius), GLint(slices), GLint(stacks) ) -> None
T aglutWireSphere
glutWireSphere
uglutWireTeapot( GLdouble(size) ) -> None
T aglutWireTeapot
glutWireTeapot
uglutWireTetrahedron(  ) -> None
T aglutWireTetrahedron
glutWireTetrahedron
uglutWireTorus( GLdouble(innerRadius), GLdouble(outerRadius), GLint(sides), GLint(rings) ) -> None
T aglutWireTorus
glutWireTorus
L  aGLUT_ACCUM
aGLUT_ACTIVE_ALT
aGLUT_ACTIVE_CTRL
aGLUT_ACTIVE_SHIFT
aGLUT_ALPHA
aGLUT_API_VERSION
aGLUT_BLUE
aGLUT_CURSOR_BOTTOM_LEFT_CORNER
aGLUT_CURSOR_BOTTOM_RIGHT_CORNER
aGLUT_CURSOR_BOTTOM_SIDE
aGLUT_CURSOR_CROSSHAIR
aGLUT_CURSOR_CYCLE
aGLUT_CURSOR_DESTROY
aGLUT_CURSOR_FULL_CROSSHAIR
aGLUT_CURSOR_HELP
aGLUT_CURSOR_INFO
aGLUT_CURSOR_INHERIT
aGLUT_CURSOR_LEFT_ARROW
aGLUT_CURSOR_LEFT_RIGHT
aGLUT_CURSOR_LEFT_SIDE
aGLUT_CURSOR_NONE
aGLUT_CURSOR_RIGHT_ARROW
aGLUT_CURSOR_RIGHT_SIDE
aGLUT_CURSOR_SPRAY
aGLUT_CURSOR_TEXT
aGLUT_CURSOR_TOP_LEFT_CORNER
aGLUT_CURSOR_TOP_RIGHT_CORNER
aGLUT_CURSOR_TOP_SIDE
aGLUT_CURSOR_UP_DOWN
aGLUT_CURSOR_WAIT
aGLUT_DEPTH
aGLUT_DEVICE_IGNORE_KEY_REPEAT
aGLUT_DEVICE_KEY_REPEAT
aGLUT_DISPLAY_MODE_POSSIBLE
aGLUT_DOUBLE
aGLUT_DOWN
aGLUT_ELAPSED_TIME
aGLUT_ENTERED
aGLUT_FULLY_COVERED
aGLUT_FULLY_RETAINED
aGLUT_GAME_MODE_ACTIVE
aGLUT_GAME_MODE_DISPLAY_CHANGED
aGLUT_GAME_MODE_HEIGHT
aGLUT_GAME_MODE_PIXEL_DEPTH
aGLUT_GAME_MODE_POSSIBLE
aGLUT_GAME_MODE_REFRESH_RATE
aGLUT_GAME_MODE_WIDTH
aGLUT_GREEN
aGLUT_HAS_DIAL_AND_BUTTON_BOX
aGLUT_HAS_JOYSTICK
aGLUT_HAS_KEYBOARD
aGLUT_HAS_MOUSE
aGLUT_HAS_OVERLAY
aGLUT_HAS_SPACEBALL
aGLUT_HAS_TABLET
aGLUT_HIDDEN
aGLUT_INDEX
aGLUT_INIT_DISPLAY_MODE
aGLUT_INIT_STATE
aGLUT_INIT_WINDOW_HEIGHT
aGLUT_INIT_WINDOW_WIDTH
aGLUT_INIT_WINDOW_X
aGLUT_INIT_WINDOW_Y
aGLUT_JOYSTICK_AXES
aGLUT_JOYSTICK_BUTTONS
aGLUT_JOYSTICK_BUTTON_A
aGLUT_JOYSTICK_BUTTON_B
aGLUT_JOYSTICK_BUTTON_C
aGLUT_JOYSTICK_BUTTON_D
aGLUT_JOYSTICK_POLL_RATE
aGLUT_KEY_DOWN
aGLUT_KEY_END
aGLUT_KEY_F1
aGLUT_KEY_F10
aGLUT_KEY_F11
aGLUT_KEY_F12
aGLUT_KEY_F2
aGLUT_KEY_F3
aGLUT_KEY_F4
aGLUT_KEY_F5
aGLUT_KEY_F6
aGLUT_KEY_F7
aGLUT_KEY_F8
aGLUT_KEY_F9
aGLUT_KEY_HOME
aGLUT_KEY_INSERT
aGLUT_KEY_LEFT
aGLUT_KEY_PAGE_DOWN
aGLUT_KEY_PAGE_UP
aGLUT_KEY_REPEAT_DEFAULT
aGLUT_KEY_REPEAT_OFF
aGLUT_KEY_REPEAT_ON
aGLUT_KEY_RIGHT
aGLUT_KEY_UP
aGLUT_LAYER_IN_USE
aGLUT_LEFT
aGLUT_LEFT_BUTTON
aGLUT_LUMINANCE
aGLUT_MENU_IN_USE
aGLUT_MENU_NOT_IN_USE
aGLUT_MENU_NUM_ITEMS
aGLUT_MIDDLE_BUTTON
aGLUT_MULTISAMPLE
aGLUT_NORMAL
aGLUT_NORMAL_DAMAGED
aGLUT_NOT_VISIBLE
aGLUT_NUM_BUTTON_BOX_BUTTONS
aGLUT_NUM_DIALS
aGLUT_NUM_MOUSE_BUTTONS
aGLUT_NUM_SPACEBALL_BUTTONS
aGLUT_NUM_TABLET_BUTTONS
aGLUT_OVERLAY
aGLUT_OVERLAY_DAMAGED
aGLUT_OVERLAY_POSSIBLE
aGLUT_OWNS_JOYSTICK
aGLUT_PARTIALLY_RETAINED
aGLUT_RED
aGLUT_RGB
aGLUT_RGBA
aGLUT_RIGHT_BUTTON
aGLUT_SCREEN_HEIGHT
aGLUT_SCREEN_HEIGHT_MM
aGLUT_SCREEN_WIDTH
aGLUT_SCREEN_WIDTH_MM
aGLUT_SINGLE
aGLUT_STENCIL
aGLUT_STEREO
aGLUT_TRANSPARENT_INDEX
aGLUT_UP
aGLUT_VIDEO_RESIZE_HEIGHT
aGLUT_VIDEO_RESIZE_HEIGHT_DELTA
aGLUT_VIDEO_RESIZE_IN_USE
aGLUT_VIDEO_RESIZE_POSSIBLE
aGLUT_VIDEO_RESIZE_WIDTH
aGLUT_VIDEO_RESIZE_WIDTH_DELTA
aGLUT_VIDEO_RESIZE_X
aGLUT_VIDEO_RESIZE_X_DELTA
aGLUT_VIDEO_RESIZE_Y
aGLUT_VIDEO_RESIZE_Y_DELTA
aGLUT_VISIBLE
aGLUT_WINDOW_ACCUM_ALPHA_SIZE
aGLUT_WINDOW_ACCUM_BLUE_SIZE
aGLUT_WINDOW_ACCUM_GREEN_SIZE
aGLUT_WINDOW_ACCUM_RED_SIZE
aGLUT_WINDOW_ALPHA_SIZE
aGLUT_WINDOW_BLUE_SIZE
aGLUT_WINDOW_BUFFER_SIZE
aGLUT_WINDOW_COLORMAP_SIZE
aGLUT_WINDOW_CURSOR
aGLUT_WINDOW_DEPTH_SIZE
aGLUT_WINDOW_DOUBLEBUFFER
aGLUT_WINDOW_FORMAT_ID
aGLUT_WINDOW_GREEN_SIZE
aGLUT_WINDOW_HEIGHT
aGLUT_WINDOW_NUM_CHILDREN
aGLUT_WINDOW_NUM_SAMPLES
aGLUT_WINDOW_PARENT
aGLUT_WINDOW_RED_SIZE
aGLUT_WINDOW_RGBA
aGLUT_WINDOW_STENCIL_SIZE
aGLUT_WINDOW_STEREO
aGLUT_WINDOW_WIDTH
aGLUT_WINDOW_X
aGLUT_WINDOW_Y
aGLUT_XLIB_IMPLEMENTATION
aGLdouble
aGLenum
aGLfloat
aGLint
glutAddMenuEntry
glutAddSubMenu
glutAttachMenu
glutBitmapCharacter
glutBitmapLength
glutBitmapWidth
glutButtonBoxFunc
glutChangeToMenuEntry
glutChangeToSubMenu
glutCopyColormap
glutCreateMenu
glutCreateSubWindow
glutCreateWindow
glutDestroyMenu
glutDestroyWindow
glutDetachMenu
glutDeviceGet
glutDialsFunc
glutDisplayFunc
glutEnterGameMode
glutEntryFunc
glutEstablishOverlay
glutExtensionSupported
glutForceJoystickFunc
glutFullScreen
glutGameModeGet
glutGameModeString
glutGet
glutGetColor
glutGetMenu
glutGetModifiers
glutGetWindow
glutHideOverlay
glutHideWindow
glutIconifyWindow
glutIdleFunc
glutIgnoreKeyRepeat
glutInit
glutInitDisplayMode
glutInitDisplayString
glutInitWindowPosition
glutInitWindowSize
glutJoystickFunc
glutKeyboardFunc
glutKeyboardUpFunc
glutLayerGet
glutLeaveGameMode
glutMainLoop
glutMenuStateFunc
glutMenuStatusFunc
glutMotionFunc
glutMouseFunc
glutOverlayDisplayFunc
glutPassiveMotionFunc
glutPopWindow
glutPositionWindow
glutPostOverlayRedisplay
glutPostRedisplay
glutPostWindowOverlayRedisplay
glutPostWindowRedisplay
glutPushWindow
glutRemoveMenuItem
glutRemoveOverlay
glutReportErrors
glutReshapeFunc
glutReshapeWindow
glutSetColor
glutSetCursor
glutSetIconTitle
glutSetKeyRepeat
glutSetMenu
glutSetWindow
glutSetWindowTitle
glutSetupVideoResizing
glutShowOverlay
glutShowWindow
glutSolidCone
glutSolidCube
glutSolidDodecahedron
glutSolidIcosahedron
glutSolidOctahedron
glutSolidSphere
glutSolidTeapot
glutSolidTetrahedron
glutSolidTorus
glutSpaceballButtonFunc
glutSpaceballMotionFunc
glutSpaceballRotateFunc
glutSpecialFunc
glutSpecialUpFunc
glutStopVideoResizing
glutStrokeCharacter
glutStrokeLength
glutStrokeWidth
glutSwapBuffers
glutTabletButtonFunc
glutTabletMotionFunc
glutTimerFunc
glutUseLayer
glutVideoPan
glutVideoResize
glutVideoResizeGet
glutVisibilityFunc
glutWarpPointer
glutWindowStatusFunc
glutWireCone
glutWireCube
glutWireDodecahedron
glutWireIcosahedron
glutWireOctahedron
glutWireSphere
glutWireTeapot
glutWireTetrahedron
glutWireTorus
a__all__
uOpenGL\raw\GLUT\__init__.py
u<module OpenGL.raw.GLUT>
T a__class__
T acls
value

.OpenGL.raw.GLUT.constants
L+
b a__doc__
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
T aGLUT_ACCUM
l aGLUT_ACCUM
T aGLUT_ACTIVE_ALT
l aGLUT_ACTIVE_ALT
T aGLUT_ACTIVE_CTRL
l aGLUT_ACTIVE_CTRL
T aGLUT_ACTIVE_SHIFT
l aGLUT_ACTIVE_SHIFT
T aGLUT_ALPHA
l aGLUT_ALPHA
T aGLUT_API_VERSION
l aGLUT_API_VERSION
T aGLUT_BLUE
l aGLUT_BLUE
T aGLUT_CURSOR_BOTTOM_LEFT_CORNER
l aGLUT_CURSOR_BOTTOM_LEFT_CORNER
T aGLUT_CURSOR_BOTTOM_RIGHT_CORNER
l aGLUT_CURSOR_BOTTOM_RIGHT_CORNER
T aGLUT_CURSOR_BOTTOM_SIDE
laGLUT_CURSOR_BOTTOM_SIDE
T aGLUT_CURSOR_CROSSHAIR
l	aGLUT_CURSOR_CROSSHAIR
T aGLUT_CURSOR_CYCLE
l aGLUT_CURSOR_CYCLE
T aGLUT_CURSOR_DESTROY
l aGLUT_CURSOR_DESTROY
T aGLUT_CURSOR_FULL_CROSSHAIR
lfaGLUT_CURSOR_FULL_CROSSHAIR
T aGLUT_CURSOR_HELP
l aGLUT_CURSOR_HELP
T aGLUT_CURSOR_INFO
l aGLUT_CURSOR_INFO
T aGLUT_CURSOR_INHERIT
ldaGLUT_CURSOR_INHERIT
T aGLUT_CURSOR_LEFT_ARROW
l aGLUT_CURSOR_LEFT_ARROW
T aGLUT_CURSOR_LEFT_RIGHT
l aGLUT_CURSOR_LEFT_RIGHT
T aGLUT_CURSOR_LEFT_SIDE
l aGLUT_CURSOR_LEFT_SIDE
T aGLUT_CURSOR_NONE
leaGLUT_CURSOR_NONE
T aGLUT_CURSOR_RIGHT_ARROW
l
aGLUT_CURSOR_RIGHT_ARROW
T aGLUT_CURSOR_RIGHT_SIDE
l aGLUT_CURSOR_RIGHT_SIDE
T aGLUT_CURSOR_SPRAY
l aGLUT_CURSOR_SPRAY
T aGLUT_CURSOR_TEXT
l aGLUT_CURSOR_TEXT
T aGLUT_CURSOR_TOP_LEFT_CORNER
l aGLUT_CURSOR_TOP_LEFT_CORNER
T aGLUT_CURSOR_TOP_RIGHT_CORNER
l aGLUT_CURSOR_TOP_RIGHT_CORNER
T aGLUT_CURSOR_TOP_SIDE
l aGLUT_CURSOR_TOP_SIDE
T aGLUT_CURSOR_UP_DOWN
l
aGLUT_CURSOR_UP_DOWN
T aGLUT_CURSOR_WAIT
l aGLUT_CURSOR_WAIT
T aGLUT_DEPTH
l aGLUT_DEPTH
T aGLUT_DEVICE_IGNORE_KEY_REPEAT
l  aGLUT_DEVICE_IGNORE_KEY_REPEAT
T aGLUT_DEVICE_KEY_REPEAT
l  aGLUT_DEVICE_KEY_REPEAT
T aGLUT_DISPLAY_MODE_POSSIBLE
l  aGLUT_DISPLAY_MODE_POSSIBLE
T aGLUT_DOUBLE
l aGLUT_DOUBLE
T aGLUT_DOWN
l
aGLUT_DOWN
T aGLUT_ELAPSED_TIME
l  aGLUT_ELAPSED_TIME
T aGLUT_ENTERED
l aGLUT_ENTERED
T aGLUT_FULLY_COVERED
l aGLUT_FULLY_COVERED
T aGLUT_FULLY_RETAINED
l aGLUT_FULLY_RETAINED
T aGLUT_GAME_MODE_ACTIVE
l
aGLUT_GAME_MODE_ACTIVE
T aGLUT_GAME_MODE_DISPLAY_CHANGED
l aGLUT_GAME_MODE_DISPLAY_CHANGED
T aGLUT_GAME_MODE_HEIGHT
l aGLUT_GAME_MODE_HEIGHT
T aGLUT_GAME_MODE_PIXEL_DEPTH
l aGLUT_GAME_MODE_PIXEL_DEPTH
T aGLUT_GAME_MODE_POSSIBLE
l aGLUT_GAME_MODE_POSSIBLE
T aGLUT_GAME_MODE_REFRESH_RATE
l aGLUT_GAME_MODE_REFRESH_RATE
T aGLUT_GAME_MODE_WIDTH
l aGLUT_GAME_MODE_WIDTH
T aGLUT_GREEN
l aGLUT_GREEN
T aGLUT_HAS_DIAL_AND_BUTTON_BOX
l  aGLUT_HAS_DIAL_AND_BUTTON_BOX
T aGLUT_HAS_JOYSTICK
l  aGLUT_HAS_JOYSTICK
T aGLUT_HAS_KEYBOARD
l  aGLUT_HAS_KEYBOARD
T aGLUT_HAS_MOUSE
l  aGLUT_HAS_MOUSE
T aGLUT_HAS_OVERLAY
l  aGLUT_HAS_OVERLAY
T aGLUT_HAS_SPACEBALL
l  aGLUT_HAS_SPACEBALL
T aGLUT_HAS_TABLET
l  aGLUT_HAS_TABLET
T aGLUT_HIDDEN
l
aGLUT_HIDDEN
T aGLUT_INDEX
l aGLUT_INDEX
T aGLUT_INIT_DISPLAY_MODE
l  aGLUT_INIT_DISPLAY_MODE
T aGLUT_INIT_STATE
l|aGLUT_INIT_STATE
T aGLUT_INIT_WINDOW_HEIGHT
l  aGLUT_INIT_WINDOW_HEIGHT
T aGLUT_INIT_WINDOW_WIDTH
l  aGLUT_INIT_WINDOW_WIDTH
T aGLUT_INIT_WINDOW_X
l  aGLUT_INIT_WINDOW_X
T aGLUT_INIT_WINDOW_Y
l  aGLUT_INIT_WINDOW_Y
T aGLUT_JOYSTICK_AXES
l  aGLUT_JOYSTICK_AXES
T aGLUT_JOYSTICK_BUTTONS
l  aGLUT_JOYSTICK_BUTTONS
T aGLUT_JOYSTICK_BUTTON_A
l aGLUT_JOYSTICK_BUTTON_A
T aGLUT_JOYSTICK_BUTTON_B
l aGLUT_JOYSTICK_BUTTON_B
T aGLUT_JOYSTICK_BUTTON_C
l aGLUT_JOYSTICK_BUTTON_C
T aGLUT_JOYSTICK_BUTTON_D
l aGLUT_JOYSTICK_BUTTON_D
T aGLUT_JOYSTICK_POLL_RATE
l  aGLUT_JOYSTICK_POLL_RATE
T aGLUT_KEY_DOWN
lgaGLUT_KEY_DOWN
T aGLUT_KEY_END
lkaGLUT_KEY_END
T aGLUT_KEY_F1
l aGLUT_KEY_F1
T aGLUT_KEY_F10
l
aGLUT_KEY_F10
T aGLUT_KEY_F11
l aGLUT_KEY_F11
T aGLUT_KEY_F12
l aGLUT_KEY_F12
T aGLUT_KEY_F2
l aGLUT_KEY_F2
T aGLUT_KEY_F3
l aGLUT_KEY_F3
T aGLUT_KEY_F4
l aGLUT_KEY_F4
T aGLUT_KEY_F5
l aGLUT_KEY_F5
T aGLUT_KEY_F6
l aGLUT_KEY_F6
T aGLUT_KEY_F7
l aGLUT_KEY_F7
T aGLUT_KEY_F8
l aGLUT_KEY_F8
T aGLUT_KEY_F9
l	aGLUT_KEY_F9
T aGLUT_KEY_HOME
ljaGLUT_KEY_HOME
T aGLUT_KEY_INSERT
llaGLUT_KEY_INSERT
T aGLUT_KEY_LEFT
ldaGLUT_KEY_LEFT
T aGLUT_KEY_PAGE_DOWN
liaGLUT_KEY_PAGE_DOWN
T aGLUT_KEY_PAGE_UP
lhaGLUT_KEY_PAGE_UP
T aGLUT_KEY_REPEAT_DEFAULT
l aGLUT_KEY_REPEAT_DEFAULT
T aGLUT_KEY_REPEAT_OFF
l
aGLUT_KEY_REPEAT_OFF
T aGLUT_KEY_REPEAT_ON
l aGLUT_KEY_REPEAT_ON
T aGLUT_KEY_RIGHT
lfaGLUT_KEY_RIGHT
T aGLUT_KEY_UP
leaGLUT_KEY_UP
T aGLUT_LAYER_IN_USE
l  aGLUT_LAYER_IN_USE
T aGLUT_LEFT
l
aGLUT_LEFT
T aGLUT_LEFT_BUTTON
l
aGLUT_LEFT_BUTTON
T aGLUT_LUMINANCE
l  aGLUT_LUMINANCE
T aGLUT_MENU_IN_USE
l aGLUT_MENU_IN_USE
T aGLUT_MENU_NOT_IN_USE
l
aGLUT_MENU_NOT_IN_USE
T aGLUT_MENU_NUM_ITEMS
l  aGLUT_MENU_NUM_ITEMS
T aGLUT_MIDDLE_BUTTON
l aGLUT_MIDDLE_BUTTON
T aGLUT_MULTISAMPLE
l  aGLUT_MULTISAMPLE
T aGLUT_NORMAL
l
aGLUT_NORMAL
T aGLUT_NORMAL_DAMAGED
l  aGLUT_NORMAL_DAMAGED
T aGLUT_NOT_VISIBLE
l
aGLUT_NOT_VISIBLE
T aGLUT_NUM_BUTTON_BOX_BUTTONS
l  aGLUT_NUM_BUTTON_BOX_BUTTONS
T aGLUT_NUM_DIALS
l  aGLUT_NUM_DIALS
T aGLUT_NUM_MOUSE_BUTTONS
l  aGLUT_NUM_MOUSE_BUTTONS
T aGLUT_NUM_SPACEBALL_BUTTONS
l  aGLUT_NUM_SPACEBALL_BUTTONS
T aGLUT_NUM_TABLET_BUTTONS
l  aGLUT_NUM_TABLET_BUTTONS
T aGLUT_OVERLAY
l aGLUT_OVERLAY
T aGLUT_OVERLAY_DAMAGED
l  aGLUT_OVERLAY_DAMAGED
T aGLUT_OVERLAY_POSSIBLE
l  aGLUT_OVERLAY_POSSIBLE
T aGLUT_OWNS_JOYSTICK
l  aGLUT_OWNS_JOYSTICK
T aGLUT_PARTIALLY_RETAINED
l aGLUT_PARTIALLY_RETAINED
T aGLUT_RED
l
aGLUT_RED
T aGLUT_RGB
l
aGLUT_RGB
T aGLUT_RGBA
l
aGLUT_RGBA
T aGLUT_RIGHT_BUTTON
l aGLUT_RIGHT_BUTTON
T aGLUT_SCREEN_HEIGHT
l  aGLUT_SCREEN_HEIGHT
T aGLUT_SCREEN_HEIGHT_MM
l  aGLUT_SCREEN_HEIGHT_MM
T aGLUT_SCREEN_WIDTH
l  aGLUT_SCREEN_WIDTH
T aGLUT_SCREEN_WIDTH_MM
l  aGLUT_SCREEN_WIDTH_MM
T aGLUT_SINGLE
l
aGLUT_SINGLE
T aGLUT_STENCIL
l aGLUT_STENCIL
T aGLUT_STEREO
l  aGLUT_STEREO
T aGLUT_TRANSPARENT_INDEX
l  aGLUT_TRANSPARENT_INDEX
T aGLUT_UP
l aGLUT_UP
T aGLUT_VIDEO_RESIZE_HEIGHT
l  aGLUT_VIDEO_RESIZE_HEIGHT
T aGLUT_VIDEO_RESIZE_HEIGHT_DELTA
l  aGLUT_VIDEO_RESIZE_HEIGHT_DELTA
T aGLUT_VIDEO_RESIZE_IN_USE
l  aGLUT_VIDEO_RESIZE_IN_USE
T aGLUT_VIDEO_RESIZE_POSSIBLE
l  aGLUT_VIDEO_RESIZE_POSSIBLE
T aGLUT_VIDEO_RESIZE_WIDTH
l  aGLUT_VIDEO_RESIZE_WIDTH
T aGLUT_VIDEO_RESIZE_WIDTH_DELTA
l  aGLUT_VIDEO_RESIZE_WIDTH_DELTA
T aGLUT_VIDEO_RESIZE_X
l  aGLUT_VIDEO_RESIZE_X
T aGLUT_VIDEO_RESIZE_X_DELTA
l  aGLUT_VIDEO_RESIZE_X_DELTA
T aGLUT_VIDEO_RESIZE_Y
l  aGLUT_VIDEO_RESIZE_Y
T aGLUT_VIDEO_RESIZE_Y_DELTA
l  aGLUT_VIDEO_RESIZE_Y_DELTA
T aGLUT_VISIBLE
l aGLUT_VISIBLE
T aGLUT_WINDOW_ACCUM_ALPHA_SIZE
lraGLUT_WINDOW_ACCUM_ALPHA_SIZE
T aGLUT_WINDOW_ACCUM_BLUE_SIZE
lqaGLUT_WINDOW_ACCUM_BLUE_SIZE
T aGLUT_WINDOW_ACCUM_GREEN_SIZE
lpaGLUT_WINDOW_ACCUM_GREEN_SIZE
T aGLUT_WINDOW_ACCUM_RED_SIZE
loaGLUT_WINDOW_ACCUM_RED_SIZE
T aGLUT_WINDOW_ALPHA_SIZE
lnaGLUT_WINDOW_ALPHA_SIZE
T aGLUT_WINDOW_BLUE_SIZE
lmaGLUT_WINDOW_BLUE_SIZE
T aGLUT_WINDOW_BUFFER_SIZE
lhaGLUT_WINDOW_BUFFER_SIZE
T aGLUT_WINDOW_COLORMAP_SIZE
lwaGLUT_WINDOW_COLORMAP_SIZE
T aGLUT_WINDOW_CURSOR
lzaGLUT_WINDOW_CURSOR
T aGLUT_WINDOW_DEPTH_SIZE
ljaGLUT_WINDOW_DEPTH_SIZE
T aGLUT_WINDOW_DOUBLEBUFFER
lsaGLUT_WINDOW_DOUBLEBUFFER
T aGLUT_WINDOW_FORMAT_ID
l{aGLUT_WINDOW_FORMAT_ID
T aGLUT_WINDOW_GREEN_SIZE
llaGLUT_WINDOW_GREEN_SIZE
T aGLUT_WINDOW_HEIGHT
lgaGLUT_WINDOW_HEIGHT
T aGLUT_WINDOW_NUM_CHILDREN
lvaGLUT_WINDOW_NUM_CHILDREN
T aGLUT_WINDOW_NUM_SAMPLES
lxaGLUT_WINDOW_NUM_SAMPLES
T aGLUT_WINDOW_PARENT
luaGLUT_WINDOW_PARENT
T aGLUT_WINDOW_RED_SIZE
lkaGLUT_WINDOW_RED_SIZE
T aGLUT_WINDOW_RGBA
ltaGLUT_WINDOW_RGBA
T aGLUT_WINDOW_STENCIL_SIZE
liaGLUT_WINDOW_STENCIL_SIZE
T aGLUT_WINDOW_STEREO
lyaGLUT_WINDOW_STEREO
T aGLUT_WINDOW_WIDTH
lfaGLUT_WINDOW_WIDTH
T aGLUT_WINDOW_X
ldaGLUT_WINDOW_X
T aGLUT_WINDOW_Y
leaGLUT_WINDOW_Y
T aGLUT_XLIB_IMPLEMENTATION
laGLUT_XLIB_IMPLEMENTATION
L  aGLUT_ACCUM
aGLUT_ACTIVE_ALT
aGLUT_ACTIVE_CTRL
aGLUT_ACTIVE_SHIFT
aGLUT_ALPHA
aGLUT_API_VERSION
aGLUT_BLUE
aGLUT_CURSOR_BOTTOM_LEFT_CORNER
aGLUT_CURSOR_BOTTOM_RIGHT_CORNER
aGLUT_CURSOR_BOTTOM_SIDE
aGLUT_CURSOR_CROSSHAIR
aGLUT_CURSOR_CYCLE
aGLUT_CURSOR_DESTROY
aGLUT_CURSOR_FULL_CROSSHAIR
aGLUT_CURSOR_HELP
aGLUT_CURSOR_INFO
aGLUT_CURSOR_INHERIT
aGLUT_CURSOR_LEFT_ARROW
aGLUT_CURSOR_LEFT_RIGHT
aGLUT_CURSOR_LEFT_SIDE
aGLUT_CURSOR_NONE
aGLUT_CURSOR_RIGHT_ARROW
aGLUT_CURSOR_RIGHT_SIDE
aGLUT_CURSOR_SPRAY
aGLUT_CURSOR_TEXT
aGLUT_CURSOR_TOP_LEFT_CORNER
aGLUT_CURSOR_TOP_RIGHT_CORNER
aGLUT_CURSOR_TOP_SIDE
aGLUT_CURSOR_UP_DOWN
aGLUT_CURSOR_WAIT
aGLUT_DEPTH
aGLUT_DEVICE_IGNORE_KEY_REPEAT
aGLUT_DEVICE_KEY_REPEAT
aGLUT_DISPLAY_MODE_POSSIBLE
aGLUT_DOUBLE
aGLUT_DOWN
aGLUT_ELAPSED_TIME
aGLUT_ENTERED
aGLUT_FULLY_COVERED
aGLUT_FULLY_RETAINED
aGLUT_GAME_MODE_ACTIVE
aGLUT_GAME_MODE_DISPLAY_CHANGED
aGLUT_GAME_MODE_HEIGHT
aGLUT_GAME_MODE_PIXEL_DEPTH
aGLUT_GAME_MODE_POSSIBLE
aGLUT_GAME_MODE_REFRESH_RATE
aGLUT_GAME_MODE_WIDTH
aGLUT_GREEN
aGLUT_HAS_DIAL_AND_BUTTON_BOX
aGLUT_HAS_JOYSTICK
aGLUT_HAS_KEYBOARD
aGLUT_HAS_MOUSE
aGLUT_HAS_OVERLAY
aGLUT_HAS_SPACEBALL
aGLUT_HAS_TABLET
aGLUT_HIDDEN
aGLUT_INDEX
aGLUT_INIT_DISPLAY_MODE
aGLUT_INIT_STATE
aGLUT_INIT_WINDOW_HEIGHT
aGLUT_INIT_WINDOW_WIDTH
aGLUT_INIT_WINDOW_X
aGLUT_INIT_WINDOW_Y
aGLUT_JOYSTICK_AXES
aGLUT_JOYSTICK_BUTTONS
aGLUT_JOYSTICK_BUTTON_A
aGLUT_JOYSTICK_BUTTON_B
aGLUT_JOYSTICK_BUTTON_C
aGLUT_JOYSTICK_BUTTON_D
aGLUT_JOYSTICK_POLL_RATE
aGLUT_KEY_DOWN
aGLUT_KEY_END
aGLUT_KEY_F1
aGLUT_KEY_F10
aGLUT_KEY_F11
aGLUT_KEY_F12
aGLUT_KEY_F2
aGLUT_KEY_F3
aGLUT_KEY_F4
aGLUT_KEY_F5
aGLUT_KEY_F6
aGLUT_KEY_F7
aGLUT_KEY_F8
aGLUT_KEY_F9
aGLUT_KEY_HOME
aGLUT_KEY_INSERT
aGLUT_KEY_LEFT
aGLUT_KEY_PAGE_DOWN
aGLUT_KEY_PAGE_UP
aGLUT_KEY_REPEAT_DEFAULT
aGLUT_KEY_REPEAT_OFF
aGLUT_KEY_REPEAT_ON
aGLUT_KEY_RIGHT
aGLUT_KEY_UP
aGLUT_LAYER_IN_USE
aGLUT_LEFT
aGLUT_LEFT_BUTTON
aGLUT_LUMINANCE
aGLUT_MENU_IN_USE
aGLUT_MENU_NOT_IN_USE
aGLUT_MENU_NUM_ITEMS
aGLUT_MIDDLE_BUTTON
aGLUT_MULTISAMPLE
aGLUT_NORMAL
aGLUT_NORMAL_DAMAGED
aGLUT_NOT_VISIBLE
aGLUT_NUM_BUTTON_BOX_BUTTONS
aGLUT_NUM_DIALS
aGLUT_NUM_MOUSE_BUTTONS
aGLUT_NUM_SPACEBALL_BUTTONS
aGLUT_NUM_TABLET_BUTTONS
aGLUT_OVERLAY
aGLUT_OVERLAY_DAMAGED
aGLUT_OVERLAY_POSSIBLE
aGLUT_OWNS_JOYSTICK
aGLUT_PARTIALLY_RETAINED
aGLUT_RED
aGLUT_RGB
aGLUT_RGBA
aGLUT_RIGHT_BUTTON
aGLUT_SCREEN_HEIGHT
aGLUT_SCREEN_HEIGHT_MM
aGLUT_SCREEN_WIDTH
aGLUT_SCREEN_WIDTH_MM
aGLUT_SINGLE
aGLUT_STENCIL
aGLUT_STEREO
aGLUT_TRANSPARENT_INDEX
aGLUT_UP
aGLUT_VIDEO_RESIZE_HEIGHT
aGLUT_VIDEO_RESIZE_HEIGHT_DELTA
aGLUT_VIDEO_RESIZE_IN_USE
aGLUT_VIDEO_RESIZE_POSSIBLE
aGLUT_VIDEO_RESIZE_WIDTH
aGLUT_VIDEO_RESIZE_WIDTH_DELTA
aGLUT_VIDEO_RESIZE_X
aGLUT_VIDEO_RESIZE_X_DELTA
aGLUT_VIDEO_RESIZE_Y
aGLUT_VIDEO_RESIZE_Y_DELTA
aGLUT_VISIBLE
aGLUT_WINDOW_ACCUM_ALPHA_SIZE
aGLUT_WINDOW_ACCUM_BLUE_SIZE
aGLUT_WINDOW_ACCUM_GREEN_SIZE
aGLUT_WINDOW_ACCUM_RED_SIZE
aGLUT_WINDOW_ALPHA_SIZE
aGLUT_WINDOW_BLUE_SIZE
aGLUT_WINDOW_BUFFER_SIZE
aGLUT_WINDOW_COLORMAP_SIZE
aGLUT_WINDOW_CURSOR
aGLUT_WINDOW_DEPTH_SIZE
aGLUT_WINDOW_DOUBLEBUFFER
aGLUT_WINDOW_FORMAT_ID
aGLUT_WINDOW_GREEN_SIZE
aGLUT_WINDOW_HEIGHT
aGLUT_WINDOW_NUM_CHILDREN
aGLUT_WINDOW_NUM_SAMPLES
aGLUT_WINDOW_PARENT
aGLUT_WINDOW_RED_SIZE
aGLUT_WINDOW_RGBA
aGLUT_WINDOW_STENCIL_SIZE
aGLUT_WINDOW_STEREO
aGLUT_WINDOW_WIDTH
aGLUT_WINDOW_X
aGLUT_WINDOW_Y
aGLUT_XLIB_IMPLEMENTATION
a__all__
uOpenGL\raw\GLUT\constants.py
u<module OpenGL.raw.GLUT.constants>

.OpenGL.raw.GLX.AMD
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_OpenGL
u\not_existing
uraw\GLX\AMD
T aNUITKA_PACKAGE_OpenGL_raw
u\not_existing
uGLX\AMD
T aNUITKA_PACKAGE_OpenGL_raw_GLX
u\not_existing
aAMD
T aNUITKA_PACKAGE_OpenGL_raw_GLX_AMD
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
uOpenGL\raw\GLX\AMD\__init__.py
u<module OpenGL.raw.GLX.AMD>

.OpenGL.raw.GLX.AMD.gpu_association
R
a_p
createFunction
aPLATFORM
aGLX
aGLX_AMD_gpu_association
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_GPU_CLOCK_AMD
l CaGLX_GPU_CLOCK_AMD
T aGLX_GPU_FASTEST_TARGET_GPUS_AMD
l CaGLX_GPU_FASTEST_TARGET_GPUS_AMD
T aGLX_GPU_NUM_PIPES_AMD
l CaGLX_GPU_NUM_PIPES_AMD
T aGLX_GPU_NUM_RB_AMD
l CaGLX_GPU_NUM_RB_AMD
T aGLX_GPU_NUM_SIMD_AMD
l CaGLX_GPU_NUM_SIMD_AMD
T aGLX_GPU_NUM_SPI_AMD
l CaGLX_GPU_NUM_SPI_AMD
T aGLX_GPU_OPENGL_VERSION_STRING_AMD
l >aGLX_GPU_OPENGL_VERSION_STRING_AMD
T aGLX_GPU_RAM_AMD
l CaGLX_GPU_RAM_AMD
T aGLX_GPU_RENDERER_STRING_AMD
l >aGLX_GPU_RENDERER_STRING_AMD
T aGLX_GPU_VENDOR_AMD
l >aGLX_GPU_VENDOR_AMD
types
aGLXContext
aGLint
aGLbitfield
aGLenum
glXBlitContextFramebufferAMD
c_uint
glXCreateAssociatedContextAMD
aPOINTER
c_int
glXCreateAssociatedContextAttribsAMD
aBool
glXDeleteAssociatedContextAMD
glXGetContextGPUIDAMD
glXGetCurrentAssociatedContextAMD
glXGetGPUIDsAMD
c_void_p
glXGetGPUInfoAMD
glXMakeAssociatedContextCurrentAMD
uOpenGL\raw\GLX\AMD\gpu_association.py
u<module OpenGL.raw.GLX.AMD.gpu_association>
T afunction
T adstCtx
srcX0
srcY0
srcX1
srcY1
dstX0
dstY0
dstX1
dstY1
mask
filter
T aid
share_list
T aid
share_context
attribList
T actx
T amaxCount
ids
T aid
property
dataType
size
data

.OpenGL.raw.GLX.ARB
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_OpenGL
u\not_existing
uraw\GLX\ARB
T aNUITKA_PACKAGE_OpenGL_raw
u\not_existing
uGLX\ARB
T aNUITKA_PACKAGE_OpenGL_raw_GLX
u\not_existing
aARB
T aNUITKA_PACKAGE_OpenGL_raw_GLX_ARB
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
uOpenGL\raw\GLX\ARB\__init__.py
u<module OpenGL.raw.GLX.ARB>

.OpenGL.raw.GLX.ARB.context_flush_control
+
a_p
createFunction
aPLATFORM
aGLX
aGLX_ARB_context_flush_control
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_CONTEXT_RELEASE_BEHAVIOR_ARB
l AaGLX_CONTEXT_RELEASE_BEHAVIOR_ARB
T aGLX_CONTEXT_RELEASE_BEHAVIOR_FLUSH_ARB
l AaGLX_CONTEXT_RELEASE_BEHAVIOR_FLUSH_ARB
T aGLX_CONTEXT_RELEASE_BEHAVIOR_NONE_ARB
l
aGLX_CONTEXT_RELEASE_BEHAVIOR_NONE_ARB
uOpenGL\raw\GLX\ARB\context_flush_control.py
u<module OpenGL.raw.GLX.ARB.context_flush_control>
T afunction

.OpenGL.raw.GLX.ARB.create_context
8
a_p
createFunction
aPLATFORM
aGLX
aGLX_ARB_create_context
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_CONTEXT_DEBUG_BIT_ARB
l aGLX_CONTEXT_DEBUG_BIT_ARB
T aGLX_CONTEXT_FLAGS_ARB
l AaGLX_CONTEXT_FLAGS_ARB
T aGLX_CONTEXT_FORWARD_COMPATIBLE_BIT_ARB
l aGLX_CONTEXT_FORWARD_COMPATIBLE_BIT_ARB
T aGLX_CONTEXT_MAJOR_VERSION_ARB
l AaGLX_CONTEXT_MAJOR_VERSION_ARB
T aGLX_CONTEXT_MINOR_VERSION_ARB
l AaGLX_CONTEXT_MINOR_VERSION_ARB
types
aGLXContext
aPOINTER
aDisplay
aGLXFBConfig
aBool
c_int
glXCreateContextAttribsARB
uOpenGL\raw\GLX\ARB\create_context.py
u<module OpenGL.raw.GLX.ARB.create_context>
T afunction
T adpy
config
share_context
direct
attrib_list

.OpenGL.raw.GLX.ARB.create_context_no_error
.
'
a_p
createFunction
aPLATFORM
aGLX
aGLX_ARB_create_context_no_error
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_CONTEXT_OPENGL_NO_ERROR_ARB
l caGLX_CONTEXT_OPENGL_NO_ERROR_ARB
uOpenGL\raw\GLX\ARB\create_context_no_error.py
u<module OpenGL.raw.GLX.ARB.create_context_no_error>
T afunction

.OpenGL.raw.GLX.ARB.create_context_profile
+
a_p
createFunction
aPLATFORM
aGLX
aGLX_ARB_create_context_profile
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_CONTEXT_COMPATIBILITY_PROFILE_BIT_ARB
l aGLX_CONTEXT_COMPATIBILITY_PROFILE_BIT_ARB
T aGLX_CONTEXT_CORE_PROFILE_BIT_ARB
l aGLX_CONTEXT_CORE_PROFILE_BIT_ARB
T aGLX_CONTEXT_PROFILE_MASK_ARB
l   aGLX_CONTEXT_PROFILE_MASK_ARB
uOpenGL\raw\GLX\ARB\create_context_profile.py
u<module OpenGL.raw.GLX.ARB.create_context_profile>
T afunction

.OpenGL.raw.GLX.ARB.create_context_robustness
-
a_p
createFunction
aPLATFORM
aGLX
aGLX_ARB_create_context_robustness
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_CONTEXT_RESET_NOTIFICATION_STRATEGY_ARB
l   aGLX_CONTEXT_RESET_NOTIFICATION_STRATEGY_ARB
T aGLX_CONTEXT_ROBUST_ACCESS_BIT_ARB
l aGLX_CONTEXT_ROBUST_ACCESS_BIT_ARB
T aGLX_LOSE_CONTEXT_ON_RESET_ARB
l   aGLX_LOSE_CONTEXT_ON_RESET_ARB
T aGLX_NO_RESET_NOTIFICATION_ARB
l   aGLX_NO_RESET_NOTIFICATION_ARB
uOpenGL\raw\GLX\ARB\create_context_robustness.py
u<module OpenGL.raw.GLX.ARB.create_context_robustness>
T afunction

.OpenGL.raw.GLX.ARB.fbconfig_float
7
)
a_p
createFunction
aPLATFORM
aGLX
aGLX_ARB_fbconfig_float
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_RGBA_FLOAT_BIT_ARB
l aGLX_RGBA_FLOAT_BIT_ARB
T aGLX_RGBA_FLOAT_TYPE_ARB
l AaGLX_RGBA_FLOAT_TYPE_ARB
uOpenGL\raw\GLX\ARB\fbconfig_float.py
u<module OpenGL.raw.GLX.ARB.fbconfig_float>
T afunction

.OpenGL.raw.GLX.ARB.framebuffer_sRGB
'
a_p
createFunction
aPLATFORM
aGLX
aGLX_ARB_framebuffer_sRGB
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_FRAMEBUFFER_SRGB_CAPABLE_ARB
l AaGLX_FRAMEBUFFER_SRGB_CAPABLE_ARB
uOpenGL\raw\GLX\ARB\framebuffer_sRGB.py
u<module OpenGL.raw.GLX.ARB.framebuffer_sRGB>
T afunction

.OpenGL.raw.GLX.ARB.get_proc_address
*
a_p
createFunction
aPLATFORM
aGLX
aGLX_ARB_get_proc_address
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
a__GLXextFuncPtr
aGLubyteArray
glXGetProcAddressARB
uOpenGL\raw\GLX\ARB\get_proc_address.py
u<module OpenGL.raw.GLX.ARB.get_proc_address>
T afunction
T aprocName

.OpenGL.raw.GLX.ARB.multisample
!
)
a_p
createFunction
aPLATFORM
aGLX
aGLX_ARB_multisample
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_SAMPLES_ARB
l   aGLX_SAMPLES_ARB
T aGLX_SAMPLE_BUFFERS_ARB
l   aGLX_SAMPLE_BUFFERS_ARB
uOpenGL\raw\GLX\ARB\multisample.py
u<module OpenGL.raw.GLX.ARB.multisample>
T afunction

.OpenGL.raw.GLX.ARB.robustness_application_isolation
P
'
a_p
createFunction
aPLATFORM
aGLX
aGLX_ARB_robustness_application_isolation
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_CONTEXT_RESET_ISOLATION_BIT_ARB
l aGLX_CONTEXT_RESET_ISOLATION_BIT_ARB
uOpenGL\raw\GLX\ARB\robustness_application_isolation.py
u<module OpenGL.raw.GLX.ARB.robustness_application_isolation>
T afunction

.OpenGL.raw.GLX.ARB.robustness_share_group_isolation
P
'
a_p
createFunction
aPLATFORM
aGLX
aGLX_ARB_robustness_share_group_isolation
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_CONTEXT_RESET_ISOLATION_BIT_ARB
l aGLX_CONTEXT_RESET_ISOLATION_BIT_ARB
uOpenGL\raw\GLX\ARB\robustness_share_group_isolation.py
u<module OpenGL.raw.GLX.ARB.robustness_share_group_isolation>
T afunction

.OpenGL.raw.GLX.ARB.vertex_buffer_object
G
'
a_p
createFunction
aPLATFORM
aGLX
aGLX_ARB_vertex_buffer_object
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_CONTEXT_ALLOW_BUFFER_BYTE_ORDER_MISMATCH_ARB
l AaGLX_CONTEXT_ALLOW_BUFFER_BYTE_ORDER_MISMATCH_ARB
uOpenGL\raw\GLX\ARB\vertex_buffer_object.py
u<module OpenGL.raw.GLX.ARB.vertex_buffer_object>
T afunction

.OpenGL.raw.GLX.DFX
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_OpenGL
u\not_existing
uraw\GLX\DFX
T aNUITKA_PACKAGE_OpenGL_raw
u\not_existing
uGLX\DFX
T aNUITKA_PACKAGE_OpenGL_raw_GLX
u\not_existing
aDFX
T aNUITKA_PACKAGE_OpenGL_raw_GLX_DFX
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
uOpenGL\raw\GLX\DFX\__init__.py
u<module OpenGL.raw.GLX.DFX>

.OpenGL.raw.GLX.DFX.multisample
%
)
a_p
createFunction
aPLATFORM
aGLX
aGLX_DFX_multisample
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_SAMPLES_3DFX
l   aGLX_SAMPLES_3DFX
T aGLX_SAMPLE_BUFFERS_3DFX
l   aGLX_SAMPLE_BUFFERS_3DFX
uOpenGL\raw\GLX\DFX\multisample.py
u<module OpenGL.raw.GLX.DFX.multisample>
T afunction

.OpenGL.raw.GLX.EXT.buffer_age
'
a_p
createFunction
aPLATFORM
aGLX
aGLX_EXT_buffer_age
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_BACK_BUFFER_AGE_EXT
l AaGLX_BACK_BUFFER_AGE_EXT
uOpenGL\raw\GLX\EXT\buffer_age.py
u<module OpenGL.raw.GLX.EXT.buffer_age>
T afunction

.OpenGL.raw.GLX.EXT
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_OpenGL
u\not_existing
uraw\GLX\EXT
T aNUITKA_PACKAGE_OpenGL_raw
u\not_existing
uGLX\EXT
T aNUITKA_PACKAGE_OpenGL_raw_GLX
u\not_existing
aEXT
T aNUITKA_PACKAGE_OpenGL_raw_GLX_EXT
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
uOpenGL\raw\GLX\EXT\__init__.py
u<module OpenGL.raw.GLX.EXT>

.OpenGL.raw.GLX.EXT.context_priority
-
a_p
createFunction
aPLATFORM
aGLX
aGLX_EXT_context_priority
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_CONTEXT_PRIORITY_HIGH_EXT
l baGLX_CONTEXT_PRIORITY_HIGH_EXT
T aGLX_CONTEXT_PRIORITY_LEVEL_EXT
l baGLX_CONTEXT_PRIORITY_LEVEL_EXT
T aGLX_CONTEXT_PRIORITY_LOW_EXT
l baGLX_CONTEXT_PRIORITY_LOW_EXT
T aGLX_CONTEXT_PRIORITY_MEDIUM_EXT
l baGLX_CONTEXT_PRIORITY_MEDIUM_EXT
uOpenGL\raw\GLX\EXT\context_priority.py
u<module OpenGL.raw.GLX.EXT.context_priority>
T afunction

.OpenGL.raw.GLX.EXT.create_context_es2_profile
6
'
a_p
createFunction
aPLATFORM
aGLX
aGLX_EXT_create_context_es2_profile
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_CONTEXT_ES2_PROFILE_BIT_EXT
l aGLX_CONTEXT_ES2_PROFILE_BIT_EXT
uOpenGL\raw\GLX\EXT\create_context_es2_profile.py
u<module OpenGL.raw.GLX.EXT.create_context_es2_profile>
T afunction

.OpenGL.raw.GLX.EXT.create_context_es_profile
1
'
a_p
createFunction
aPLATFORM
aGLX
aGLX_EXT_create_context_es_profile
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_CONTEXT_ES_PROFILE_BIT_EXT
l aGLX_CONTEXT_ES_PROFILE_BIT_EXT
uOpenGL\raw\GLX\EXT\create_context_es_profile.py
u<module OpenGL.raw.GLX.EXT.create_context_es_profile>
T afunction

.OpenGL.raw.GLX.EXT.fbconfig_packed_float
p
)
a_p
createFunction
aPLATFORM
aGLX
aGLX_EXT_fbconfig_packed_float
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_RGBA_UNSIGNED_FLOAT_BIT_EXT
l aGLX_RGBA_UNSIGNED_FLOAT_BIT_EXT
T aGLX_RGBA_UNSIGNED_FLOAT_TYPE_EXT
l AaGLX_RGBA_UNSIGNED_FLOAT_TYPE_EXT
uOpenGL\raw\GLX\EXT\fbconfig_packed_float.py
u<module OpenGL.raw.GLX.EXT.fbconfig_packed_float>
T afunction

.OpenGL.raw.GLX.EXT.framebuffer_sRGB
'
a_p
createFunction
aPLATFORM
aGLX
aGLX_EXT_framebuffer_sRGB
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_FRAMEBUFFER_SRGB_CAPABLE_EXT
l AaGLX_FRAMEBUFFER_SRGB_CAPABLE_EXT
uOpenGL\raw\GLX\EXT\framebuffer_sRGB.py
u<module OpenGL.raw.GLX.EXT.framebuffer_sRGB>
T afunction

.OpenGL.raw.GLX.EXT.get_drawable_type
'
a_p
createFunction
aPLATFORM
aGLX
aGLX_EXT_get_drawable_type
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_DRAWABLE_TYPE
l   aGLX_DRAWABLE_TYPE
uOpenGL\raw\GLX\EXT\get_drawable_type.py
u<module OpenGL.raw.GLX.EXT.get_drawable_type>
T afunction

.OpenGL.raw.GLX.EXT.import_context
H
:
a_p
createFunction
aPLATFORM
aGLX
aGLX_EXT_import_context
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_SCREEN_EXT
l   aGLX_SCREEN_EXT
T aGLX_SHARE_CONTEXT_EXT
l   aGLX_SHARE_CONTEXT_EXT
T aGLX_VISUAL_ID_EXT
l   aGLX_VISUAL_ID_EXT
types
aPOINTER
aDisplay
aGLXContext
glXFreeContextEXT
aGLXContextID
glXGetContextIDEXT
glXGetCurrentDisplayEXT
glXImportContextEXT
c_int
glXQueryContextInfoEXT
uOpenGL\raw\GLX\EXT\import_context.py
u<module OpenGL.raw.GLX.EXT.import_context>
T afunction
T adpy
context
T acontext
T adpy
contextID
T adpy
context
attribute
value

.OpenGL.raw.GLX.EXT.libglvnd
'
a_p
createFunction
aPLATFORM
aGLX
aGLX_EXT_libglvnd
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_VENDOR_NAMES_EXT
l AaGLX_VENDOR_NAMES_EXT
uOpenGL\raw\GLX\EXT\libglvnd.py
u<module OpenGL.raw.GLX.EXT.libglvnd>
T afunction

.OpenGL.raw.GLX.EXT.no_config_context
%
a_p
createFunction
aPLATFORM
aGLX
aGLX_EXT_no_config_context
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
uOpenGL\raw\GLX\EXT\no_config_context.py
u<module OpenGL.raw.GLX.EXT.no_config_context>
T afunction

.OpenGL.raw.GLX.EXT.stereo_tree
`
+
a_p
createFunction
aPLATFORM
aGLX
aGLX_EXT_stereo_tree
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_STEREO_NOTIFY_EXT
l
aGLX_STEREO_NOTIFY_EXT
T aGLX_STEREO_NOTIFY_MASK_EXT
l aGLX_STEREO_NOTIFY_MASK_EXT
T aGLX_STEREO_TREE_EXT
l AaGLX_STEREO_TREE_EXT
uOpenGL\raw\GLX\EXT\stereo_tree.py
u<module OpenGL.raw.GLX.EXT.stereo_tree>
T afunction

.OpenGL.raw.GLX.EXT.swap_control
0
a_p
createFunction
aPLATFORM
aGLX
aGLX_EXT_swap_control
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_MAX_SWAP_INTERVAL_EXT
l AaGLX_MAX_SWAP_INTERVAL_EXT
T aGLX_SWAP_INTERVAL_EXT
l AaGLX_SWAP_INTERVAL_EXT
types
aPOINTER
aDisplay
aGLXDrawable
c_int
glXSwapIntervalEXT
uOpenGL\raw\GLX\EXT\swap_control.py
u<module OpenGL.raw.GLX.EXT.swap_control>
T afunction
T adpy
drawable
interval

.OpenGL.raw.GLX.EXT.swap_control_tear
'
a_p
createFunction
aPLATFORM
aGLX
aGLX_EXT_swap_control_tear
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_LATE_SWAPS_TEAR_EXT
l AaGLX_LATE_SWAPS_TEAR_EXT
uOpenGL\raw\GLX\EXT\swap_control_tear.py
u<module OpenGL.raw.GLX.EXT.swap_control_tear>
T afunction

.OpenGL.raw.GLX.EXT.texture_from_pixmap
p
a_p
createFunction
aPLATFORM
aGLX
aGLX_EXT_texture_from_pixmap
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_AUX0_EXT
l AaGLX_AUX0_EXT
T aGLX_AUX1_EXT
l AaGLX_AUX1_EXT
T aGLX_AUX2_EXT
l AaGLX_AUX2_EXT
T aGLX_AUX3_EXT
l AaGLX_AUX3_EXT
T aGLX_AUX4_EXT
l AaGLX_AUX4_EXT
T aGLX_AUX5_EXT
l AaGLX_AUX5_EXT
T aGLX_AUX6_EXT
l AaGLX_AUX6_EXT
T aGLX_AUX7_EXT
l AaGLX_AUX7_EXT
T aGLX_AUX8_EXT
l AaGLX_AUX8_EXT
T aGLX_AUX9_EXT
l AaGLX_AUX9_EXT
T aGLX_BACK_EXT
l AaGLX_BACK_EXT
T aGLX_BACK_LEFT_EXT
l AaGLX_BACK_LEFT_EXT
T aGLX_BACK_RIGHT_EXT
l AaGLX_BACK_RIGHT_EXT
T aGLX_BIND_TO_MIPMAP_TEXTURE_EXT
l AaGLX_BIND_TO_MIPMAP_TEXTURE_EXT
T aGLX_BIND_TO_TEXTURE_RGBA_EXT
l AaGLX_BIND_TO_TEXTURE_RGBA_EXT
T aGLX_BIND_TO_TEXTURE_RGB_EXT
l AaGLX_BIND_TO_TEXTURE_RGB_EXT
T aGLX_BIND_TO_TEXTURE_TARGETS_EXT
l AaGLX_BIND_TO_TEXTURE_TARGETS_EXT
T aGLX_FRONT_EXT
l AaGLX_FRONT_EXT
T aGLX_FRONT_LEFT_EXT
l AaGLX_FRONT_LEFT_EXT
T aGLX_FRONT_RIGHT_EXT
l AaGLX_FRONT_RIGHT_EXT
T aGLX_MIPMAP_TEXTURE_EXT
l AaGLX_MIPMAP_TEXTURE_EXT
T aGLX_TEXTURE_1D_BIT_EXT
l aGLX_TEXTURE_1D_BIT_EXT
T aGLX_TEXTURE_1D_EXT
l AaGLX_TEXTURE_1D_EXT
T aGLX_TEXTURE_2D_BIT_EXT
l aGLX_TEXTURE_2D_BIT_EXT
T aGLX_TEXTURE_2D_EXT
l AaGLX_TEXTURE_2D_EXT
T aGLX_TEXTURE_FORMAT_EXT
l AaGLX_TEXTURE_FORMAT_EXT
T aGLX_TEXTURE_FORMAT_NONE_EXT
l AaGLX_TEXTURE_FORMAT_NONE_EXT
T aGLX_TEXTURE_FORMAT_RGBA_EXT
l AaGLX_TEXTURE_FORMAT_RGBA_EXT
T aGLX_TEXTURE_FORMAT_RGB_EXT
l AaGLX_TEXTURE_FORMAT_RGB_EXT
T aGLX_TEXTURE_RECTANGLE_BIT_EXT
l aGLX_TEXTURE_RECTANGLE_BIT_EXT
T aGLX_TEXTURE_RECTANGLE_EXT
l AaGLX_TEXTURE_RECTANGLE_EXT
T aGLX_TEXTURE_TARGET_EXT
l AaGLX_TEXTURE_TARGET_EXT
T aGLX_Y_INVERTED_EXT
l AaGLX_Y_INVERTED_EXT
types
aPOINTER
aDisplay
aGLXDrawable
c_int
glXBindTexImageEXT
glXReleaseTexImageEXT
uOpenGL\raw\GLX\EXT\texture_from_pixmap.py
u<module OpenGL.raw.GLX.EXT.texture_from_pixmap>
T afunction
T adpy
drawable
buffer
attrib_list
T adpy
drawable
buffer

.OpenGL.raw.GLX.EXT.visual_info
=
E
a_p
createFunction
aPLATFORM
aGLX
aGLX_EXT_visual_info
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_DIRECT_COLOR_EXT
l   aGLX_DIRECT_COLOR_EXT
T aGLX_GRAY_SCALE_EXT
l   aGLX_GRAY_SCALE_EXT
T aGLX_NONE_EXT
l   aGLX_NONE_EXT
T aGLX_PSEUDO_COLOR_EXT
l   aGLX_PSEUDO_COLOR_EXT
T aGLX_STATIC_COLOR_EXT
l   aGLX_STATIC_COLOR_EXT
T aGLX_STATIC_GRAY_EXT
l   aGLX_STATIC_GRAY_EXT
T aGLX_TRANSPARENT_ALPHA_VALUE_EXT
l(aGLX_TRANSPARENT_ALPHA_VALUE_EXT
T aGLX_TRANSPARENT_BLUE_VALUE_EXT
l'aGLX_TRANSPARENT_BLUE_VALUE_EXT
T aGLX_TRANSPARENT_GREEN_VALUE_EXT
l&aGLX_TRANSPARENT_GREEN_VALUE_EXT
T aGLX_TRANSPARENT_INDEX_EXT
l   aGLX_TRANSPARENT_INDEX_EXT
T aGLX_TRANSPARENT_INDEX_VALUE_EXT
l$aGLX_TRANSPARENT_INDEX_VALUE_EXT
T aGLX_TRANSPARENT_RED_VALUE_EXT
l%aGLX_TRANSPARENT_RED_VALUE_EXT
T aGLX_TRANSPARENT_RGB_EXT
l   aGLX_TRANSPARENT_RGB_EXT
T aGLX_TRANSPARENT_TYPE_EXT
l#aGLX_TRANSPARENT_TYPE_EXT
T aGLX_TRUE_COLOR_EXT
l   aGLX_TRUE_COLOR_EXT
T aGLX_X_VISUAL_TYPE_EXT
l"aGLX_X_VISUAL_TYPE_EXT
uOpenGL\raw\GLX\EXT\visual_info.py
u<module OpenGL.raw.GLX.EXT.visual_info>
T afunction

.OpenGL.raw.GLX.EXT.visual_rating
-
a_p
createFunction
aPLATFORM
aGLX
aGLX_EXT_visual_rating
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_NONE_EXT
l   aGLX_NONE_EXT
T aGLX_NON_CONFORMANT_VISUAL_EXT
l   aGLX_NON_CONFORMANT_VISUAL_EXT
T aGLX_SLOW_VISUAL_EXT
l   aGLX_SLOW_VISUAL_EXT
T aGLX_VISUAL_CAVEAT_EXT
l aGLX_VISUAL_CAVEAT_EXT
uOpenGL\raw\GLX\EXT\visual_rating.py
u<module OpenGL.raw.GLX.EXT.visual_rating>
T afunction

.OpenGL.raw.GLX.INTEL
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_OpenGL
u\not_existing
uraw\GLX\INTEL
T aNUITKA_PACKAGE_OpenGL_raw
u\not_existing
uGLX\INTEL
T aNUITKA_PACKAGE_OpenGL_raw_GLX
u\not_existing
aINTEL
T aNUITKA_PACKAGE_OpenGL_raw_GLX_INTEL
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
uOpenGL\raw\GLX\INTEL\__init__.py
u<module OpenGL.raw.GLX.INTEL>

.OpenGL.raw.GLX.INTEL.swap_event
-
a_p
createFunction
aPLATFORM
aGLX
aGLX_INTEL_swap_event
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_BUFFER_SWAP_COMPLETE_INTEL_MASK
l    aGLX_BUFFER_SWAP_COMPLETE_INTEL_MASK
T aGLX_COPY_COMPLETE_INTEL
l   aGLX_COPY_COMPLETE_INTEL
T aGLX_EXCHANGE_COMPLETE_INTEL
l   aGLX_EXCHANGE_COMPLETE_INTEL
T aGLX_FLIP_COMPLETE_INTEL
l   aGLX_FLIP_COMPLETE_INTEL
uOpenGL\raw\GLX\INTEL\swap_event.py
u<module OpenGL.raw.GLX.INTEL.swap_event>
T afunction

.OpenGL.raw.GLX.MESA.agp_offset
*
a_p
createFunction
aPLATFORM
aGLX
aGLX_MESA_agp_offset
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
c_uint
c_void_p
glXGetAGPOffsetMESA
uOpenGL\raw\GLX\MESA\agp_offset.py
u<module OpenGL.raw.GLX.MESA.agp_offset>
T afunction
T apointer

.OpenGL.raw.GLX.MESA
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_OpenGL
u\not_existing
uraw\GLX\MESA
T aNUITKA_PACKAGE_OpenGL_raw
u\not_existing
uGLX\MESA
T aNUITKA_PACKAGE_OpenGL_raw_GLX
u\not_existing
aMESA
T aNUITKA_PACKAGE_OpenGL_raw_GLX_MESA
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
uOpenGL\raw\GLX\MESA\__init__.py
u<module OpenGL.raw.GLX.MESA>

.OpenGL.raw.GLX.MESA.copy_sub_buffer
9
,
a_p
createFunction
aPLATFORM
aGLX
aGLX_MESA_copy_sub_buffer
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
aPOINTER
aDisplay
aGLXDrawable
c_int
glXCopySubBufferMESA
uOpenGL\raw\GLX\MESA\copy_sub_buffer.py
u<module OpenGL.raw.GLX.MESA.copy_sub_buffer>
T afunction
T adpy
drawable
wxwyawidth
height

.OpenGL.raw.GLX.MESA.pixmap_colormap
J
.
a_p
createFunction
aPLATFORM
aGLX
aGLX_MESA_pixmap_colormap
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
aGLXPixmap
aPOINTER
aDisplay
aXVisualInfo
aPixmap
aColormap
glXCreateGLXPixmapMESA
uOpenGL\raw\GLX\MESA\pixmap_colormap.py
u<module OpenGL.raw.GLX.MESA.pixmap_colormap>
T afunction
T adpy
visual
pixmap
cmap

.OpenGL.raw.GLX.MESA.query_renderer
J
a_p
createFunction
aPLATFORM
aGLX
aGLX_MESA_query_renderer
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_RENDERER_ACCELERATED_MESA
l   aGLX_RENDERER_ACCELERATED_MESA
T aGLX_RENDERER_DEVICE_ID_MESA
l   aGLX_RENDERER_DEVICE_ID_MESA
T aGLX_RENDERER_OPENGL_COMPATIBILITY_PROFILE_VERSION_MESA
l   aGLX_RENDERER_OPENGL_COMPATIBILITY_PROFILE_VERSION_MESA
T aGLX_RENDERER_OPENGL_CORE_PROFILE_VERSION_MESA
l   aGLX_RENDERER_OPENGL_CORE_PROFILE_VERSION_MESA
T aGLX_RENDERER_OPENGL_ES2_PROFILE_VERSION_MESA
l   aGLX_RENDERER_OPENGL_ES2_PROFILE_VERSION_MESA
T aGLX_RENDERER_OPENGL_ES_PROFILE_VERSION_MESA
l   aGLX_RENDERER_OPENGL_ES_PROFILE_VERSION_MESA
T aGLX_RENDERER_PREFERRED_PROFILE_MESA
l   aGLX_RENDERER_PREFERRED_PROFILE_MESA
T aGLX_RENDERER_UNIFIED_MEMORY_ARCHITECTURE_MESA
l   aGLX_RENDERER_UNIFIED_MEMORY_ARCHITECTURE_MESA
T aGLX_RENDERER_VENDOR_ID_MESA
l   aGLX_RENDERER_VENDOR_ID_MESA
T aGLX_RENDERER_VERSION_MESA
l   aGLX_RENDERER_VERSION_MESA
T aGLX_RENDERER_VIDEO_MEMORY_MESA
l   aGLX_RENDERER_VIDEO_MEMORY_MESA
types
aBool
c_int
aPOINTER
c_uint
glXQueryCurrentRendererIntegerMESA
c_char_p
glXQueryCurrentRendererStringMESA
aDisplay
glXQueryRendererIntegerMESA
glXQueryRendererStringMESA
uOpenGL\raw\GLX\MESA\query_renderer.py
u<module OpenGL.raw.GLX.MESA.query_renderer>
T afunction
T aattribute
value
T aattribute
T adpy
screen
renderer
attribute
value
T adpy
screen
renderer
attribute

.OpenGL.raw.GLX.MESA.release_buffers
&
,
a_p
createFunction
aPLATFORM
aGLX
aGLX_MESA_release_buffers
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
aBool
aPOINTER
aDisplay
aGLXDrawable
glXReleaseBuffersMESA
uOpenGL\raw\GLX\MESA\release_buffers.py
u<module OpenGL.raw.GLX.MESA.release_buffers>
T afunction
T adpy
drawable

.OpenGL.raw.GLX.MESA.set_3dfx_mode
}
.
a_p
createFunction
aPLATFORM
aGLX
aGLX_MESA_set_3dfx_mode
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_3DFX_FULLSCREEN_MODE_MESA
l aGLX_3DFX_FULLSCREEN_MODE_MESA
T aGLX_3DFX_WINDOW_MODE_MESA
l aGLX_3DFX_WINDOW_MODE_MESA
types
aGLboolean
aGLint
glXSet3DfxModeMESA
uOpenGL\raw\GLX\MESA\set_3dfx_mode.py
u<module OpenGL.raw.GLX.MESA.set_3dfx_mode>
T afunction
T amode

.OpenGL.raw.GLX.MESA.swap_control
+
a_p
createFunction
aPLATFORM
aGLX
aGLX_MESA_swap_control
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
c_int
glXGetSwapIntervalMESA
c_uint
glXSwapIntervalMESA
uOpenGL\raw\GLX\MESA\swap_control.py
u<module OpenGL.raw.GLX.MESA.swap_control>
T afunction
T ainterval

.OpenGL.raw.GLX.NV
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_OpenGL
u\not_existing
uraw\GLX\NV
T aNUITKA_PACKAGE_OpenGL_raw
u\not_existing
uGLX\NV
T aNUITKA_PACKAGE_OpenGL_raw_GLX
u\not_existing
aNV
T aNUITKA_PACKAGE_OpenGL_raw_GLX_NV
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
uOpenGL\raw\GLX\NV\__init__.py
u<module OpenGL.raw.GLX.NV>

.OpenGL.raw.GLX.NV.copy_buffer
1
a_p
createFunction
aPLATFORM
aGLX
aGLX_NV_copy_buffer
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
aPOINTER
aDisplay
aGLXContext
aGLenum
aGLintptr
aGLsizeiptr
glXCopyBufferSubDataNV
aGLuint
glXNamedCopyBufferSubDataNV
uOpenGL\raw\GLX\NV\copy_buffer.py
u<module OpenGL.raw.GLX.NV.copy_buffer>
T afunction
T adpy
readCtx
writeCtx
readTarget
writeTarget
readOffset
writeOffset
size
T adpy
readCtx
writeCtx
readBuffer
writeBuffer
readOffset
writeOffset
size

.OpenGL.raw.GLX.NV.copy_image
/
a_p
createFunction
aPLATFORM
aGLX
aGLX_NV_copy_image
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
aPOINTER
aDisplay
aGLXContext
aGLuint
aGLenum
aGLint
aGLsizei
glXCopyImageSubDataNV
uOpenGL\raw\GLX\NV\copy_image.py
u<module OpenGL.raw.GLX.NV.copy_image>
T afunction
T adpy
srcCtx
srcName
srcTarget
srcLevel
srcX
srcY
srcZ
dstCtx
dstName
dstTarget
dstLevel
dstX
dstY
dstZ
width
height
depth

.OpenGL.raw.GLX.NV.delay_before_swap
7
-
a_p
createFunction
aPLATFORM
aGLX
aGLX_NV_delay_before_swap
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
aBool
aPOINTER
aDisplay
aGLXDrawable
aGLfloat
glXDelayBeforeSwapNV
uOpenGL\raw\GLX\NV\delay_before_swap.py
u<module OpenGL.raw.GLX.NV.delay_before_swap>
T afunction
T adpy
drawable
seconds

.OpenGL.raw.GLX.NV.float_buffer
'
a_p
createFunction
aPLATFORM
aGLX
aGLX_NV_float_buffer
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_FLOAT_COMPONENTS_NV
l AaGLX_FLOAT_COMPONENTS_NV
uOpenGL\raw\GLX\NV\float_buffer.py
u<module OpenGL.raw.GLX.NV.float_buffer>
T afunction

.OpenGL.raw.GLX.NV.multigpu_context
/
a_p
createFunction
aPLATFORM
aGLX
aGLX_NV_multigpu_context
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_CONTEXT_MULTIGPU_ATTRIB_AFR_NV
l AaGLX_CONTEXT_MULTIGPU_ATTRIB_AFR_NV
T aGLX_CONTEXT_MULTIGPU_ATTRIB_MULTICAST_NV
l AaGLX_CONTEXT_MULTIGPU_ATTRIB_MULTICAST_NV
T aGLX_CONTEXT_MULTIGPU_ATTRIB_MULTI_DISPLAY_MULTICAST_NV
l AaGLX_CONTEXT_MULTIGPU_ATTRIB_MULTI_DISPLAY_MULTICAST_NV
T aGLX_CONTEXT_MULTIGPU_ATTRIB_NV
l AaGLX_CONTEXT_MULTIGPU_ATTRIB_NV
T aGLX_CONTEXT_MULTIGPU_ATTRIB_SINGLE_NV
l AaGLX_CONTEXT_MULTIGPU_ATTRIB_SINGLE_NV
uOpenGL\raw\GLX\NV\multigpu_context.py
u<module OpenGL.raw.GLX.NV.multigpu_context>
T afunction

.OpenGL.raw.GLX.NV.multisample_coverage
D
)
a_p
createFunction
aPLATFORM
aGLX
aGLX_NV_multisample_coverage
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_COLOR_SAMPLES_NV
l AaGLX_COLOR_SAMPLES_NV
T aGLX_COVERAGE_SAMPLES_NV
l   aGLX_COVERAGE_SAMPLES_NV
uOpenGL\raw\GLX\NV\multisample_coverage.py
u<module OpenGL.raw.GLX.NV.multisample_coverage>
T afunction

.OpenGL.raw.GLX.NV.present_video
0
a_p
createFunction
aPLATFORM
aGLX
aGLX_NV_present_video
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_NUM_VIDEO_SLOTS_NV
l AaGLX_NUM_VIDEO_SLOTS_NV
types
c_int
aPOINTER
aDisplay
c_uint
glXBindVideoDeviceNV
glXEnumerateVideoDevicesNV
uOpenGL\raw\GLX\NV\present_video.py
u<module OpenGL.raw.GLX.NV.present_video>
T afunction
T adpy
video_slot
video_device
attrib_list
T adpy
screen
nelements

.OpenGL.raw.GLX.NV.robustness_video_memory_purge
U
'
a_p
createFunction
aPLATFORM
aGLX
aGLX_NV_robustness_video_memory_purge
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_GENERATE_RESET_ON_VIDEO_MEMORY_PURGE_NV
l AaGLX_GENERATE_RESET_ON_VIDEO_MEMORY_PURGE_NV
uOpenGL\raw\GLX\NV\robustness_video_memory_purge.py
u<module OpenGL.raw.GLX.NV.robustness_video_memory_purge>
T afunction

.OpenGL.raw.GLX.NV.swap_group
%
9
a_p
createFunction
aPLATFORM
aGLX
aGLX_NV_swap_group
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
aBool
aPOINTER
aDisplay
aGLuint
glXBindSwapBarrierNV
aGLXDrawable
glXJoinSwapGroupNV
c_int
aGLuintArray
glXQueryFrameCountNV
glXQueryMaxSwapGroupsNV
glXQuerySwapGroupNV
glXResetFrameCountNV
uOpenGL\raw\GLX\NV\swap_group.py
u<module OpenGL.raw.GLX.NV.swap_group>
T afunction
T adpy
group
barrier
T adpy
drawable
group
T adpy
screen
count
T adpy
screen
maxGroups
maxBarriers
T adpy
drawable
group
barrier
T adpy
screen

.OpenGL.raw.GLX.NV.video_capture
:
a_p
createFunction
aPLATFORM
aGLX
aGLX_NV_video_capture
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_DEVICE_ID_NV
l AaGLX_DEVICE_ID_NV
T aGLX_NUM_VIDEO_CAPTURE_SLOTS_NV
l AaGLX_NUM_VIDEO_CAPTURE_SLOTS_NV
T aGLX_UNIQUE_ID_NV
l AaGLX_UNIQUE_ID_NV
types
c_int
aPOINTER
aDisplay
c_uint
aGLXVideoCaptureDeviceNV
glXBindVideoCaptureDeviceNV
glXEnumerateVideoCaptureDevicesNV
glXLockVideoCaptureDeviceNV
glXQueryVideoCaptureDeviceNV
glXReleaseVideoCaptureDeviceNV
uOpenGL\raw\GLX\NV\video_capture.py
u<module OpenGL.raw.GLX.NV.video_capture>
T afunction
T adpy
video_capture_slot
device
T adpy
screen
nelements
T adpy
device
T adpy
device
attribute
value

.OpenGL.raw.GLX.NV.video_out
M
a_p
createFunction
aPLATFORM
aGLX
aGLX_NV_video_out
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_VIDEO_OUT_ALPHA_NV
l AaGLX_VIDEO_OUT_ALPHA_NV
T aGLX_VIDEO_OUT_COLOR_AND_ALPHA_NV
l AaGLX_VIDEO_OUT_COLOR_AND_ALPHA_NV
T aGLX_VIDEO_OUT_COLOR_AND_DEPTH_NV
l AaGLX_VIDEO_OUT_COLOR_AND_DEPTH_NV
T aGLX_VIDEO_OUT_COLOR_NV
l AaGLX_VIDEO_OUT_COLOR_NV
T aGLX_VIDEO_OUT_DEPTH_NV
l AaGLX_VIDEO_OUT_DEPTH_NV
T aGLX_VIDEO_OUT_FIELD_1_NV
l AaGLX_VIDEO_OUT_FIELD_1_NV
T aGLX_VIDEO_OUT_FIELD_2_NV
l AaGLX_VIDEO_OUT_FIELD_2_NV
T aGLX_VIDEO_OUT_FRAME_NV
l AaGLX_VIDEO_OUT_FRAME_NV
T aGLX_VIDEO_OUT_STACKED_FIELDS_1_2_NV
l AaGLX_VIDEO_OUT_STACKED_FIELDS_1_2_NV
T aGLX_VIDEO_OUT_STACKED_FIELDS_2_1_NV
l AaGLX_VIDEO_OUT_STACKED_FIELDS_2_1_NV
types
c_int
aPOINTER
aDisplay
aGLXVideoDeviceNV
aGLXPbuffer
glXBindVideoImageNV
glXGetVideoDeviceNV
c_ulong
glXGetVideoInfoNV
glXReleaseVideoDeviceNV
glXReleaseVideoImageNV
aGLboolean
glXSendPbufferToVideoNV
uOpenGL\raw\GLX\NV\video_out.py
u<module OpenGL.raw.GLX.NV.video_out>
T afunction
T adpy
aVideoDevice
pbuf
iVideoBuffer
T adpy
screen
numVideoDevices
pVideoDevice
T adpy
screen
aVideoDevice
pulCounterOutputPbuffer
pulCounterOutputVideo
T adpy
screen
aVideoDevice
T adpy
pbuf
T adpy
pbuf
iBufferType
pulCounterPbuffer
bBlock

.OpenGL.raw.GLX.NV.video_output
M
a_p
createFunction
aPLATFORM
aGLX
aGLX_NV_video_output
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_VIDEO_OUT_ALPHA_NV
l AaGLX_VIDEO_OUT_ALPHA_NV
T aGLX_VIDEO_OUT_COLOR_AND_ALPHA_NV
l AaGLX_VIDEO_OUT_COLOR_AND_ALPHA_NV
T aGLX_VIDEO_OUT_COLOR_AND_DEPTH_NV
l AaGLX_VIDEO_OUT_COLOR_AND_DEPTH_NV
T aGLX_VIDEO_OUT_COLOR_NV
l AaGLX_VIDEO_OUT_COLOR_NV
T aGLX_VIDEO_OUT_DEPTH_NV
l AaGLX_VIDEO_OUT_DEPTH_NV
T aGLX_VIDEO_OUT_FIELD_1_NV
l AaGLX_VIDEO_OUT_FIELD_1_NV
T aGLX_VIDEO_OUT_FIELD_2_NV
l AaGLX_VIDEO_OUT_FIELD_2_NV
T aGLX_VIDEO_OUT_FRAME_NV
l AaGLX_VIDEO_OUT_FRAME_NV
T aGLX_VIDEO_OUT_STACKED_FIELDS_1_2_NV
l AaGLX_VIDEO_OUT_STACKED_FIELDS_1_2_NV
T aGLX_VIDEO_OUT_STACKED_FIELDS_2_1_NV
l AaGLX_VIDEO_OUT_STACKED_FIELDS_2_1_NV
types
c_int
aPOINTER
aDisplay
aGLXVideoDeviceNV
aGLXPbuffer
glXBindVideoImageNV
glXGetVideoDeviceNV
c_ulong
glXGetVideoInfoNV
glXReleaseVideoDeviceNV
glXReleaseVideoImageNV
aGLboolean
glXSendPbufferToVideoNV
uOpenGL\raw\GLX\NV\video_output.py
u<module OpenGL.raw.GLX.NV.video_output>
T afunction
T adpy
aVideoDevice
pbuf
iVideoBuffer
T adpy
screen
numVideoDevices
pVideoDevice
T adpy
screen
aVideoDevice
pulCounterOutputPbuffer
pulCounterOutputVideo
T adpy
screen
aVideoDevice
T adpy
pbuf
T adpy
pbuf
iBufferType
pulCounterPbuffer
bBlock

.OpenGL.raw.GLX.OML
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_OpenGL
u\not_existing
uraw\GLX\OML
T aNUITKA_PACKAGE_OpenGL_raw
u\not_existing
uGLX\OML
T aNUITKA_PACKAGE_OpenGL_raw_GLX
u\not_existing
aOML
T aNUITKA_PACKAGE_OpenGL_raw_GLX_OML
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
uOpenGL\raw\GLX\OML\__init__.py
u<module OpenGL.raw.GLX.OML>

.OpenGL.raw.GLX.OML.swap_method
-
a_p
createFunction
aPLATFORM
aGLX
aGLX_OML_swap_method
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_SWAP_COPY_OML
l   aGLX_SWAP_COPY_OML
T aGLX_SWAP_EXCHANGE_OML
l   aGLX_SWAP_EXCHANGE_OML
T aGLX_SWAP_METHOD_OML
l   aGLX_SWAP_METHOD_OML
T aGLX_SWAP_UNDEFINED_OML
l   aGLX_SWAP_UNDEFINED_OML
uOpenGL\raw\GLX\OML\swap_method.py
u<module OpenGL.raw.GLX.OML.swap_method>
T afunction

.OpenGL.raw.GLX.OML.sync_control
K
6
a_p
createFunction
aPLATFORM
aGLX
aGLX_OML_sync_control
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
aBool
aPOINTER
aDisplay
aGLXDrawable
int32_t
glXGetMscRateOML
int64_t
glXGetSyncValuesOML
glXSwapBuffersMscOML
glXWaitForMscOML
glXWaitForSbcOML
uOpenGL\raw\GLX\OML\sync_control.py
u<module OpenGL.raw.GLX.OML.sync_control>
T afunction
T adpy
drawable
numerator
denominator
T adpy
drawable
ust
msc
sbc
T adpy
drawable
target_msc
divisor
remainder
T adpy
drawable
target_msc
divisor
remainder
ust
msc
sbc
T adpy
drawable
target_sbc
ust
msc
sbc

.OpenGL.raw.GLX.SGI
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_OpenGL
u\not_existing
uraw\GLX\SGI
T aNUITKA_PACKAGE_OpenGL_raw
u\not_existing
uGLX\SGI
T aNUITKA_PACKAGE_OpenGL_raw_GLX
u\not_existing
aSGI
T aNUITKA_PACKAGE_OpenGL_raw_GLX_SGI
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
uOpenGL\raw\GLX\SGI\__init__.py
u<module OpenGL.raw.GLX.SGI>

.OpenGL.raw.GLX.SGI.cushion
,
a_p
createFunction
aPLATFORM
aGLX
aGLX_SGI_cushion
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
aPOINTER
aDisplay
aWindow
c_float
glXCushionSGI
uOpenGL\raw\GLX\SGI\cushion.py
u<module OpenGL.raw.GLX.SGI.cushion>
T afunction
T adpy
window
cushion

.OpenGL.raw.GLX.SGI.make_current_read
Z
.
a_p
createFunction
aPLATFORM
aGLX
aGLX_SGI_make_current_read
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
aGLXDrawable
glXGetCurrentReadDrawableSGI
aBool
aPOINTER
aDisplay
aGLXContext
glXMakeCurrentReadSGI
uOpenGL\raw\GLX\SGI\make_current_read.py
u<module OpenGL.raw.GLX.SGI.make_current_read>
T afunction
T adpy
draw
read
ctx

.OpenGL.raw.GLX.SGI.swap_control
)
a_p
createFunction
aPLATFORM
aGLX
aGLX_SGI_swap_control
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
c_int
glXSwapIntervalSGI
uOpenGL\raw\GLX\SGI\swap_control.py
u<module OpenGL.raw.GLX.SGI.swap_control>
T afunction
T ainterval

.OpenGL.raw.GLX.SGI.video_sync
.
-
a_p
createFunction
aPLATFORM
aGLX
aGLX_SGI_video_sync
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
c_int
aPOINTER
c_uint
glXGetVideoSyncSGI
glXWaitVideoSyncSGI
uOpenGL\raw\GLX\SGI\video_sync.py
u<module OpenGL.raw.GLX.SGI.video_sync>
T afunction
T acount
T adivisor
remainder
count

.OpenGL.raw.GLX.SGIS.blended_overlay
'
a_p
createFunction
aPLATFORM
aGLX
aGLX_SGIS_blended_overlay
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_BLENDED_RGBA_SGIS
l   aGLX_BLENDED_RGBA_SGIS
uOpenGL\raw\GLX\SGIS\blended_overlay.py
u<module OpenGL.raw.GLX.SGIS.blended_overlay>
T afunction

.OpenGL.raw.GLX.SGIS
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_OpenGL
u\not_existing
uraw\GLX\SGIS
T aNUITKA_PACKAGE_OpenGL_raw
u\not_existing
uGLX\SGIS
T aNUITKA_PACKAGE_OpenGL_raw_GLX
u\not_existing
aSGIS
T aNUITKA_PACKAGE_OpenGL_raw_GLX_SGIS
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
uOpenGL\raw\GLX\SGIS\__init__.py
u<module OpenGL.raw.GLX.SGIS>

.OpenGL.raw.GLX.SGIS.multisample
(
)
a_p
createFunction
aPLATFORM
aGLX
aGLX_SGIS_multisample
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_SAMPLES_SGIS
l   aGLX_SAMPLES_SGIS
T aGLX_SAMPLE_BUFFERS_SGIS
l   aGLX_SAMPLE_BUFFERS_SGIS
uOpenGL\raw\GLX\SGIS\multisample.py
u<module OpenGL.raw.GLX.SGIS.multisample>
T afunction

.OpenGL.raw.GLX.SGIS.shared_multisample
}
)
a_p
createFunction
aPLATFORM
aGLX
aGLX_SGIS_shared_multisample
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_MULTISAMPLE_SUB_RECT_HEIGHT_SGIS
l   aGLX_MULTISAMPLE_SUB_RECT_HEIGHT_SGIS
T aGLX_MULTISAMPLE_SUB_RECT_WIDTH_SGIS
l   aGLX_MULTISAMPLE_SUB_RECT_WIDTH_SGIS
uOpenGL\raw\GLX\SGIS\shared_multisample.py
u<module OpenGL.raw.GLX.SGIS.shared_multisample>
T afunction

.OpenGL.raw.GLX.SGIX
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_OpenGL
u\not_existing
uraw\GLX\SGIX
T aNUITKA_PACKAGE_OpenGL_raw
u\not_existing
uGLX\SGIX
T aNUITKA_PACKAGE_OpenGL_raw_GLX
u\not_existing
aSGIX
T aNUITKA_PACKAGE_OpenGL_raw_GLX_SGIX
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
uOpenGL\raw\GLX\SGIX\__init__.py
u<module OpenGL.raw.GLX.SGIX>

.OpenGL.raw.GLX.SGIX.dmbuffer
0
a_p
createFunction
aPLATFORM
aGLX
aGLX_SGIX_dmbuffer
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_DIGITAL_MEDIA_PBUFFER_SGIX
l   aGLX_DIGITAL_MEDIA_PBUFFER_SGIX
types
aBool
aPOINTER
aDisplay
aGLXPbufferSGIX
aDMparams
aDMbuffer
glXAssociateDMPbufferSGIX
uOpenGL\raw\GLX\SGIX\dmbuffer.py
u<module OpenGL.raw.GLX.SGIX.dmbuffer>
T afunction
T adpy
pbuffer
params
dmbuffer

.OpenGL.raw.GLX.SGIX.fbconfig
Q
a_p
createFunction
aPLATFORM
aGLX
aGLX_SGIX_fbconfig
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_COLOR_INDEX_BIT_SGIX
l aGLX_COLOR_INDEX_BIT_SGIX
T aGLX_COLOR_INDEX_TYPE_SGIX
l   aGLX_COLOR_INDEX_TYPE_SGIX
T aGLX_DRAWABLE_TYPE_SGIX
l   aGLX_DRAWABLE_TYPE_SGIX
T aGLX_FBCONFIG_ID_SGIX
l   aGLX_FBCONFIG_ID_SGIX
T aGLX_PIXMAP_BIT_SGIX
l aGLX_PIXMAP_BIT_SGIX
T aGLX_RENDER_TYPE_SGIX
l   aGLX_RENDER_TYPE_SGIX
T aGLX_RGBA_BIT_SGIX
l aGLX_RGBA_BIT_SGIX
T aGLX_RGBA_TYPE_SGIX
l   aGLX_RGBA_TYPE_SGIX
T aGLX_SCREEN_EXT
l   aGLX_SCREEN_EXT
T aGLX_WINDOW_BIT_SGIX
l aGLX_WINDOW_BIT_SGIX
T aGLX_X_RENDERABLE_SGIX
l   aGLX_X_RENDERABLE_SGIX
types
aPOINTER
aGLXFBConfigSGIX
aDisplay
c_int
glXChooseFBConfigSGIX
aGLXContext
aBool
glXCreateContextWithConfigSGIX
aGLXPixmap
aPixmap
glXCreateGLXPixmapWithConfigSGIX
glXGetFBConfigAttribSGIX
aXVisualInfo
glXGetFBConfigFromVisualSGIX
glXGetVisualFromFBConfigSGIX
uOpenGL\raw\GLX\SGIX\fbconfig.py
u<module OpenGL.raw.GLX.SGIX.fbconfig>
T afunction
T adpy
screen
attrib_list
nelements
T adpy
config
render_type
share_list
direct
T adpy
config
pixmap
T adpy
config
attribute
value
T adpy
vis
T adpy
config

.OpenGL.raw.GLX.SGIX.hyperpipe
U
O
a_p
createFunction
aPLATFORM
aGLX
aGLX_SGIX_hyperpipe
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_BAD_HYPERPIPE_CONFIG_SGIX
l[aGLX_BAD_HYPERPIPE_CONFIG_SGIX
T aGLX_BAD_HYPERPIPE_SGIX
l\aGLX_BAD_HYPERPIPE_SGIX
T aGLX_HYPERPIPE_DISPLAY_PIPE_SGIX
l aGLX_HYPERPIPE_DISPLAY_PIPE_SGIX
T aGLX_HYPERPIPE_ID_SGIX
l   aGLX_HYPERPIPE_ID_SGIX
T aGLX_HYPERPIPE_PIPE_NAME_LENGTH_SGIX
lPaGLX_HYPERPIPE_PIPE_NAME_LENGTH_SGIX
T aGLX_HYPERPIPE_PIXEL_AVERAGE_SGIX
l aGLX_HYPERPIPE_PIXEL_AVERAGE_SGIX
T aGLX_HYPERPIPE_RENDER_PIPE_SGIX
l aGLX_HYPERPIPE_RENDER_PIPE_SGIX
T aGLX_HYPERPIPE_STEREO_SGIX
l aGLX_HYPERPIPE_STEREO_SGIX
T aGLX_PIPE_RECT_LIMITS_SGIX
l aGLX_PIPE_RECT_LIMITS_SGIX
T aGLX_PIPE_RECT_SGIX
l aGLX_PIPE_RECT_SGIX
types
c_int
aPOINTER
aDisplay
glXBindHyperpipeSGIX
glXDestroyHyperpipeConfigSGIX
c_void_p
glXHyperpipeAttribSGIX
aGLXHyperpipeConfigSGIX
glXHyperpipeConfigSGIX
glXQueryHyperpipeAttribSGIX
glXQueryHyperpipeBestAttribSGIX
glXQueryHyperpipeConfigSGIX
aGLXHyperpipeNetworkSGIX
glXQueryHyperpipeNetworkSGIX
uOpenGL\raw\GLX\SGIX\hyperpipe.py
u<module OpenGL.raw.GLX.SGIX.hyperpipe>
T afunction
T adpy
hpId
T adpy
timeSlice
attrib
size
attribList
T adpy
networkId
npipes
cfg
hpId
T adpy
timeSlice
attrib
size
returnAttribList
T adpy
timeSlice
attrib
size
attribList
returnAttribList
T adpy
hpId
npipes
T adpy
npipes

.OpenGL.raw.GLX.SGIX.pbuffer
i
a_p
createFunction
aPLATFORM
aGLX
aGLX_SGIX_pbuffer
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_ACCUM_BUFFER_BIT_SGIX
l  aGLX_ACCUM_BUFFER_BIT_SGIX
T aGLX_AUX_BUFFERS_BIT_SGIX
l aGLX_AUX_BUFFERS_BIT_SGIX
T aGLX_BACK_LEFT_BUFFER_BIT_SGIX
l aGLX_BACK_LEFT_BUFFER_BIT_SGIX
T aGLX_BACK_RIGHT_BUFFER_BIT_SGIX
l aGLX_BACK_RIGHT_BUFFER_BIT_SGIX
T aGLX_BUFFER_CLOBBER_MASK_SGIX
l   @aGLX_BUFFER_CLOBBER_MASK_SGIX
T aGLX_DAMAGED_SGIX
l   aGLX_DAMAGED_SGIX
T aGLX_DEPTH_BUFFER_BIT_SGIX
l aGLX_DEPTH_BUFFER_BIT_SGIX
T aGLX_EVENT_MASK_SGIX
l   aGLX_EVENT_MASK_SGIX
T aGLX_FRONT_LEFT_BUFFER_BIT_SGIX
l aGLX_FRONT_LEFT_BUFFER_BIT_SGIX
T aGLX_FRONT_RIGHT_BUFFER_BIT_SGIX
l aGLX_FRONT_RIGHT_BUFFER_BIT_SGIX
T aGLX_HEIGHT_SGIX
l   aGLX_HEIGHT_SGIX
T aGLX_LARGEST_PBUFFER_SGIX
l   aGLX_LARGEST_PBUFFER_SGIX
T aGLX_MAX_PBUFFER_HEIGHT_SGIX
l   aGLX_MAX_PBUFFER_HEIGHT_SGIX
T aGLX_MAX_PBUFFER_PIXELS_SGIX
l   aGLX_MAX_PBUFFER_PIXELS_SGIX
T aGLX_MAX_PBUFFER_WIDTH_SGIX
l   aGLX_MAX_PBUFFER_WIDTH_SGIX
T aGLX_OPTIMAL_PBUFFER_HEIGHT_SGIX
l   aGLX_OPTIMAL_PBUFFER_HEIGHT_SGIX
T aGLX_OPTIMAL_PBUFFER_WIDTH_SGIX
l   aGLX_OPTIMAL_PBUFFER_WIDTH_SGIX
T aGLX_PBUFFER_BIT_SGIX
l aGLX_PBUFFER_BIT_SGIX
T aGLX_PBUFFER_SGIX
l   aGLX_PBUFFER_SGIX
T aGLX_PRESERVED_CONTENTS_SGIX
l   aGLX_PRESERVED_CONTENTS_SGIX
T aGLX_SAMPLE_BUFFERS_BIT_SGIX
l  aGLX_SAMPLE_BUFFERS_BIT_SGIX
T aGLX_SAVED_SGIX
l   aGLX_SAVED_SGIX
T aGLX_STENCIL_BUFFER_BIT_SGIX
l@aGLX_STENCIL_BUFFER_BIT_SGIX
T aGLX_WIDTH_SGIX
l   aGLX_WIDTH_SGIX
T aGLX_WINDOW_SGIX
l   aGLX_WINDOW_SGIX
types
aGLXPbufferSGIX
aPOINTER
aDisplay
aGLXFBConfigSGIX
c_uint
c_int
glXCreateGLXPbufferSGIX
glXDestroyGLXPbufferSGIX
aGLXDrawable
c_ulong
glXGetSelectedEventSGIX
glXQueryGLXPbufferSGIX
glXSelectEventSGIX
uOpenGL\raw\GLX\SGIX\pbuffer.py
u<module OpenGL.raw.GLX.SGIX.pbuffer>
T afunction
T adpy
config
width
height
attrib_list
T adpy
pbuf
T adpy
drawable
mask
T adpy
pbuf
attribute
value

.OpenGL.raw.GLX.SGIX.swap_barrier
_
/
a_p
createFunction
aPLATFORM
aGLX
aGLX_SGIX_swap_barrier
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
aPOINTER
aDisplay
aGLXDrawable
c_int
glXBindSwapBarrierSGIX
aBool
glXQueryMaxSwapBarriersSGIX
uOpenGL\raw\GLX\SGIX\swap_barrier.py
u<module OpenGL.raw.GLX.SGIX.swap_barrier>
T afunction
T adpy
drawable
barrier
T adpy
screen
max

.OpenGL.raw.GLX.SGIX.swap_group
+
a_p
createFunction
aPLATFORM
aGLX
aGLX_SGIX_swap_group
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
aPOINTER
aDisplay
aGLXDrawable
glXJoinSwapGroupSGIX
uOpenGL\raw\GLX\SGIX\swap_group.py
u<module OpenGL.raw.GLX.SGIX.swap_group>
T afunction
T adpy
drawable
member

.OpenGL.raw.GLX.SGIX.video_resize
i
8
a_p
createFunction
aPLATFORM
aGLX
aGLX_SGIX_video_resize
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_SYNC_FRAME_SGIX
l
aGLX_SYNC_FRAME_SGIX
T aGLX_SYNC_SWAP_SGIX
l aGLX_SYNC_SWAP_SGIX
types
c_int
aPOINTER
aDisplay
aWindow
glXBindChannelToWindowSGIX
glXChannelRectSGIX
aGLenum
glXChannelRectSyncSGIX
glXQueryChannelDeltasSGIX
glXQueryChannelRectSGIX
uOpenGL\raw\GLX\SGIX\video_resize.py
u<module OpenGL.raw.GLX.SGIX.video_resize>
T afunction
T adisplay
screen
channel
window
T adisplay
screen
channel
wxwywwwhT adisplay
screen
channel
synctype
T adisplay
screen
channel
dx
dy
dw
dh

.OpenGL.raw.GLX.SGIX.video_source
1
a_p
createFunction
aPLATFORM
aGLX
aGLX_SGIX_video_source
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
aGLXVideoSourceSGIX
aPOINTER
aDisplay
c_int
aVLServer
aVLPath
aVLNode
glXCreateGLXVideoSourceSGIX
glXDestroyGLXVideoSourceSGIX
uOpenGL\raw\GLX\SGIX\video_source.py
u<module OpenGL.raw.GLX.SGIX.video_source>
T afunction
T adisplay
screen
server
path
nodeClass
drainNode
T adpy
glxvideosource

.OpenGL.raw.GLX.SGIX.visual_select_group
'
a_p
createFunction
aPLATFORM
aGLX
aGLX_SGIX_visual_select_group
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_VISUAL_SELECT_GROUP_SGIX
l   aGLX_VISUAL_SELECT_GROUP_SGIX
uOpenGL\raw\GLX\SGIX\visual_select_group.py
u<module OpenGL.raw.GLX.SGIX.visual_select_group>
T afunction

.OpenGL.raw.GLX.SUN
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_OpenGL
u\not_existing
uraw\GLX\SUN
T aNUITKA_PACKAGE_OpenGL_raw
u\not_existing
uGLX\SUN
T aNUITKA_PACKAGE_OpenGL_raw_GLX
u\not_existing
aSUN
T aNUITKA_PACKAGE_OpenGL_raw_GLX_SUN
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
uOpenGL\raw\GLX\SUN\__init__.py
u<module OpenGL.raw.GLX.SUN>

.OpenGL.raw.GLX.SUN.get_transparent_index
[
-
a_p
createFunction
aPLATFORM
aGLX
aGLX_SUN_get_transparent_index
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
aStatus
aPOINTER
aDisplay
aWindow
c_ulong
glXGetTransparentIndexSUN
uOpenGL\raw\GLX\SUN\get_transparent_index.py
u<module OpenGL.raw.GLX.SUN.get_transparent_index>
T afunction
T adpy
overlay
underlay
pTransparentIndex

.OpenGL.raw.GLX.VERSION.GLX_1_0
Z
a_p
createFunction
aPLATFORM
aGLX
aGLX_VERSION_GLX_1_0
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_ACCUM_ALPHA_SIZE
l aGLX_ACCUM_ALPHA_SIZE
T aGLX_ACCUM_BLUE_SIZE
l aGLX_ACCUM_BLUE_SIZE
T aGLX_ACCUM_GREEN_SIZE
l aGLX_ACCUM_GREEN_SIZE
T aGLX_ACCUM_RED_SIZE
l aGLX_ACCUM_RED_SIZE
T aGLX_ALPHA_SIZE
l aGLX_ALPHA_SIZE
T aGLX_AUX_BUFFERS
l aGLX_AUX_BUFFERS
T aGLX_BAD_ATTRIBUTE
l aGLX_BAD_ATTRIBUTE
T aGLX_BAD_CONTEXT
l aGLX_BAD_CONTEXT
T aGLX_BAD_ENUM
l aGLX_BAD_ENUM
T aGLX_BAD_SCREEN
l aGLX_BAD_SCREEN
T aGLX_BAD_VALUE
l aGLX_BAD_VALUE
T aGLX_BAD_VISUAL
l aGLX_BAD_VISUAL
T aGLX_BLUE_SIZE
l
aGLX_BLUE_SIZE
T aGLX_BUFFER_SIZE
l aGLX_BUFFER_SIZE
T aGLX_BufferSwapComplete
l aGLX_BufferSwapComplete
T aGLX_DEPTH_SIZE
l aGLX_DEPTH_SIZE
T aGLX_DOUBLEBUFFER
l aGLX_DOUBLEBUFFER
T aGLX_GREEN_SIZE
l	aGLX_GREEN_SIZE
T aGLX_LEVEL
l aGLX_LEVEL
T aGLX_NO_EXTENSION
l aGLX_NO_EXTENSION
T aGLX_PbufferClobber
l
aGLX_PbufferClobber
T aGLX_RED_SIZE
l aGLX_RED_SIZE
T aGLX_RGBA
l aGLX_RGBA
T aGLX_STENCIL_SIZE
laGLX_STENCIL_SIZE
T aGLX_STEREO
l aGLX_STEREO
T aGLX_USE_GL
l aGLX_USE_GL
T a__GLX_NUMBER_EVENTS
l a__GLX_NUMBER_EVENTS
types
aPOINTER
aXVisualInfo
aDisplay
c_int
glXChooseVisual
aGLXContext
c_ulong
glXCopyContext
aBool
glXCreateContext
aGLXPixmap
aPixmap
glXCreateGLXPixmap
glXDestroyContext
glXDestroyGLXPixmap
glXGetConfig
glXGetCurrentContext
aGLXDrawable
glXGetCurrentDrawable
glXIsDirect
glXMakeCurrent
glXQueryExtension
glXQueryVersion
glXSwapBuffers
aFont
glXUseXFont
T naglXWaitGL
glXWaitX
uOpenGL\raw\GLX\VERSION\GLX_1_0.py
u<module OpenGL.raw.GLX.VERSION.GLX_1_0>
T afunction
T adpy
screen
attribList
T adpy
src
dst
mask
T adpy
vis
shareList
direct
T adpy
visual
pixmap
T adpy
ctx
T adpy
pixmap
T adpy
visual
attrib
value
T adpy
drawable
ctx
T adpy
errorb
event
T adpy
maj
min
T adpy
drawable
T afont
first
count
list

.OpenGL.raw.GLX.VERSION.GLX_1_1
6
a_p
createFunction
aPLATFORM
aGLX
aGLX_VERSION_GLX_1_1
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_EXTENSIONS
l aGLX_EXTENSIONS
T aGLX_VENDOR
l aGLX_VENDOR
T aGLX_VERSION
l aGLX_VERSION
types
c_char_p
aPOINTER
aDisplay
c_int
glXGetClientString
glXQueryExtensionsString
glXQueryServerString
uOpenGL\raw\GLX\VERSION\GLX_1_1.py
u<module OpenGL.raw.GLX.VERSION.GLX_1_1>
T afunction
T adpy
name
T adpy
screen
T adpy
screen
name

.OpenGL.raw.GLX.VERSION.GLX_1_2
)
a_p
createFunction
aPLATFORM
aGLX
aGLX_VERSION_GLX_1_2
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
types
aPOINTER
aDisplay
glXGetCurrentDisplay
uOpenGL\raw\GLX\VERSION\GLX_1_2.py
u<module OpenGL.raw.GLX.VERSION.GLX_1_2>
T afunction

.OpenGL.raw.GLX.VERSION.GLX_1_3
a_p
createFunction
aPLATFORM
aGLX
aGLX_VERSION_GLX_1_3
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_ACCUM_BUFFER_BIT
l  aGLX_ACCUM_BUFFER_BIT
T aGLX_AUX_BUFFERS_BIT
l aGLX_AUX_BUFFERS_BIT
T aGLX_BACK_LEFT_BUFFER_BIT
l aGLX_BACK_LEFT_BUFFER_BIT
T aGLX_BACK_RIGHT_BUFFER_BIT
l aGLX_BACK_RIGHT_BUFFER_BIT
T aGLX_COLOR_INDEX_BIT
l aGLX_COLOR_INDEX_BIT
T aGLX_COLOR_INDEX_TYPE
l   aGLX_COLOR_INDEX_TYPE
T aGLX_CONFIG_CAVEAT
l aGLX_CONFIG_CAVEAT
T aGLX_DAMAGED
l   aGLX_DAMAGED
T aGLX_DEPTH_BUFFER_BIT
l aGLX_DEPTH_BUFFER_BIT
T aGLX_DIRECT_COLOR
l   aGLX_DIRECT_COLOR
T aGLX_DONT_CARE
g       aGLX_DONT_CARE
T aGLX_DRAWABLE_TYPE
l   aGLX_DRAWABLE_TYPE
T aGLX_EVENT_MASK
l   aGLX_EVENT_MASK
T aGLX_FBCONFIG_ID
l   aGLX_FBCONFIG_ID
T aGLX_FRONT_LEFT_BUFFER_BIT
l aGLX_FRONT_LEFT_BUFFER_BIT
T aGLX_FRONT_RIGHT_BUFFER_BIT
l aGLX_FRONT_RIGHT_BUFFER_BIT
T aGLX_GRAY_SCALE
l   aGLX_GRAY_SCALE
T aGLX_HEIGHT
l   aGLX_HEIGHT
T aGLX_LARGEST_PBUFFER
l   aGLX_LARGEST_PBUFFER
T aGLX_MAX_PBUFFER_HEIGHT
l   aGLX_MAX_PBUFFER_HEIGHT
T aGLX_MAX_PBUFFER_PIXELS
l   aGLX_MAX_PBUFFER_PIXELS
T aGLX_MAX_PBUFFER_WIDTH
l   aGLX_MAX_PBUFFER_WIDTH
T aGLX_NONE
l   aGLX_NONE
T aGLX_NON_CONFORMANT_CONFIG
l   aGLX_NON_CONFORMANT_CONFIG
T aGLX_PBUFFER
l   aGLX_PBUFFER
T aGLX_PBUFFER_BIT
l aGLX_PBUFFER_BIT
T aGLX_PBUFFER_CLOBBER_MASK
l   @aGLX_PBUFFER_CLOBBER_MASK
T aGLX_PBUFFER_HEIGHT
l   aGLX_PBUFFER_HEIGHT
T aGLX_PBUFFER_WIDTH
l   aGLX_PBUFFER_WIDTH
T aGLX_PIXMAP_BIT
l aGLX_PIXMAP_BIT
T aGLX_PRESERVED_CONTENTS
l   aGLX_PRESERVED_CONTENTS
T aGLX_PSEUDO_COLOR
l   aGLX_PSEUDO_COLOR
T aGLX_RENDER_TYPE
l   aGLX_RENDER_TYPE
T aGLX_RGBA_BIT
l aGLX_RGBA_BIT
T aGLX_RGBA_TYPE
l   aGLX_RGBA_TYPE
T aGLX_SAVED
l   aGLX_SAVED
T aGLX_SCREEN
l   aGLX_SCREEN
T aGLX_SLOW_CONFIG
l   aGLX_SLOW_CONFIG
T aGLX_STATIC_COLOR
l   aGLX_STATIC_COLOR
T aGLX_STATIC_GRAY
l   aGLX_STATIC_GRAY
T aGLX_STENCIL_BUFFER_BIT
l@aGLX_STENCIL_BUFFER_BIT
T aGLX_TRANSPARENT_ALPHA_VALUE
l(aGLX_TRANSPARENT_ALPHA_VALUE
T aGLX_TRANSPARENT_BLUE_VALUE
l'aGLX_TRANSPARENT_BLUE_VALUE
T aGLX_TRANSPARENT_GREEN_VALUE
l&aGLX_TRANSPARENT_GREEN_VALUE
T aGLX_TRANSPARENT_INDEX
l   aGLX_TRANSPARENT_INDEX
T aGLX_TRANSPARENT_INDEX_VALUE
l$aGLX_TRANSPARENT_INDEX_VALUE
T aGLX_TRANSPARENT_RED_VALUE
l%aGLX_TRANSPARENT_RED_VALUE
T aGLX_TRANSPARENT_RGB
l   aGLX_TRANSPARENT_RGB
T aGLX_TRANSPARENT_TYPE
l#aGLX_TRANSPARENT_TYPE
T aGLX_TRUE_COLOR
l   aGLX_TRUE_COLOR
T aGLX_VISUAL_ID
l   aGLX_VISUAL_ID
T aGLX_WIDTH
l   aGLX_WIDTH
T aGLX_WINDOW
l   aGLX_WINDOW
T aGLX_WINDOW_BIT
l aGLX_WINDOW_BIT
T aGLX_X_RENDERABLE
l   aGLX_X_RENDERABLE
T aGLX_X_VISUAL_TYPE
l"aGLX_X_VISUAL_TYPE
types
aPOINTER
aGLXFBConfig
aDisplay
c_int
glXChooseFBConfig
aGLXContext
aBool
glXCreateNewContext
aGLXPbuffer
glXCreatePbuffer
aGLXPixmap
aPixmap
glXCreatePixmap
aGLXWindow
aWindow
glXCreateWindow
glXDestroyPbuffer
glXDestroyPixmap
glXDestroyWindow
aGLXDrawable
glXGetCurrentReadDrawable
glXGetFBConfigAttrib
glXGetFBConfigs
c_ulong
glXGetSelectedEvent
aXVisualInfo
glXGetVisualFromFBConfig
glXMakeContextCurrent
glXQueryContext
c_uint
glXQueryDrawable
glXSelectEvent
uOpenGL\raw\GLX\VERSION\GLX_1_3.py
u<module OpenGL.raw.GLX.VERSION.GLX_1_3>
T afunction
T adpy
screen
attrib_list
nelements
T adpy
config
render_type
share_list
direct
T adpy
config
attrib_list
T adpy
config
pixmap
attrib_list
T adpy
config
win
attrib_list
T adpy
pbuf
T adpy
pixmap
T adpy
win
T adpy
config
attribute
value
T adpy
screen
nelements
T adpy
draw
event_mask
T adpy
config
T adpy
draw
read
ctx
T adpy
ctx
attribute
value
T adpy
draw
attribute
value

.OpenGL.raw.GLX.VERSION.GLX_1_4
V
.
a_p
createFunction
aPLATFORM
aGLX
aGLX_VERSION_GLX_1_4
a_errors
a_error_checker
T aerror_checker
a__doc__
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
uOpenGL.raw.GLX
T a_types
a_types
a_cs
uOpenGL.raw.GLX._types
T w*T a_errors
uOpenGL.constant
T aConstant
aConstant
a_C
ctypes
a_EXTENSION_NAME
a_f
T aGLX_SAMPLES
l   aGLX_SAMPLES
T aGLX_SAMPLE_BUFFERS
l   aGLX_SAMPLE_BUFFERS
types
a__GLXextFuncPtr
aGLubyteArray
glXGetProcAddress
uOpenGL\raw\GLX\VERSION\GLX_1_4.py
u<module OpenGL.raw.GLX.VERSION.GLX_1_4>
T afunction
T aprocName

.OpenGL.raw.GLX.VERSION
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_OpenGL
u\not_existing
uraw\GLX\VERSION
T aNUITKA_PACKAGE_OpenGL_raw
u\not_existing
uGLX\VERSION
T aNUITKA_PACKAGE_OpenGL_raw_GLX
u\not_existing
aVERSION
T aNUITKA_PACKAGE_OpenGL_raw_GLX_VERSION
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
uOpenGL\raw\GLX\VERSION\__init__.py
u<module OpenGL.raw.GLX.VERSION>

.OpenGL.raw.GLX._errors
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
uOpenGL.platform
T aPLATFORM
l
aPLATFORM
a_p
uOpenGL.error
T a_ErrorChecker
a_ErrorChecker
a_error_checker
uOpenGL\raw\GLX\_errors.py
u<module OpenGL.raw.GLX._errors>

.OpenGL.raw.GLX._glgets
uNeed to define a lookupint for this api
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
uOpenGL.raw.GL._lookupint
T aLookupInt
l
aLookupInt
a_L
a_glget_size_mapping
a_m
uOpenGL\raw\GLX\_glgets.py
u<module OpenGL.raw.GLX._glgets>
T aargs

.OpenGL.raw.GLX._types
uOpenGL.raw.GLX
T a_types
l
a_types
uOpenGL.platform
T actypesloader
ctypesloader
loadLibrary
cdll
aX11
aXOpenDisplay
aPOINTER
aDisplay
restype
environ
get
T aDISPLAY
aXDefaultScreen
argtypes
uOpenGL.GLX
T aglXQueryVersion
glXQueryVersion
getDisplay
c_int
utoo many values to unpack (expected 2)
value
l agetVersion
l T aglXQueryExtensionsString
glXQueryExtensionsString
getScreen
split
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
aOpenGL
T aplatform
constant
extensions
platform
a_p
constant
extensions
uOpenGL.raw.GL._types
T w*uOpenGL._bytes
T aas_8_bit
as_8_bit
c_void
void
c_uint
aBool
aExtensionQuerier
a__prepare__
a_GLXQuerier
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
