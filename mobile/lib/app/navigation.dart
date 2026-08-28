import 'package:flutter/widgets.dart';

/// The navigator every screen the app raises by itself is pushed onto.
///
/// A vault request arrives from a socket, not from a tap, so there is no
/// `BuildContext` in scope when one needs to be shown. This is that context.
/// A null `currentContext` — no activity, app killed, engine warming up — is
/// an ordinary state and the callers treat it as "cannot ask", which for an
/// approval means no.
final GlobalKey<NavigatorState> rootNavigatorKey = GlobalKey<NavigatorState>();
