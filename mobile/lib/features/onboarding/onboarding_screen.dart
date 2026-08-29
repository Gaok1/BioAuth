import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/app_controller.dart';

class OnboardingScreen extends ConsumerWidget {
  const OnboardingScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Scaffold(
      body: SafeArea(
        child: LayoutBuilder(
          builder: (context, constraints) => SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            // Spread out while it fits, scrollable once it does not. At the
            // larger accessibility text sizes this is taller than a small
            // phone, and what fell off the bottom was the button that ends
            // onboarding: the first screen of the app, with no way past it.
            //
            // The height a scroll view offers is unbounded, so the column is
            // told it is at least a screenful. That is what gives
            // `spaceBetween` something to spread — and it is why the spacing
            // is alignment rather than the `Spacer` that used to do it, since
            // a flex child in an unbounded column is an error.
            child: ConstrainedBox(
              constraints: BoxConstraints(
                minHeight: constraints.maxHeight - 48,
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  // Nothing, so that the gap above the pitch matches the gap
                  // below it: the pitch sits centred, the button at the foot.
                  const SizedBox.shrink(),
                  const _Pitch(),
                  SizedBox(
                    width: double.infinity,
                    child: FilledButton.icon(
                      onPressed: () => ref
                          .read(appControllerProvider.notifier)
                          .completeOnboarding(),
                      icon: const Icon(Icons.arrow_forward),
                      label: const Text('Começar'),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _Pitch extends StatelessWidget {
  const _Pitch();

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    mainAxisSize: MainAxisSize.min,
    children: [
      Icon(
        Icons.phonelink_lock,
        size: 72,
        color: Theme.of(context).colorScheme.primary,
      ),
      const SizedBox(height: 24),
      Text(
        'Seu telefone, sua aprovação',
        style: Theme.of(context).textTheme.headlineLarge,
      ),
      const SizedBox(height: 12),
      Text(
        'Autorize acessos locais com contexto e biometria. '
        'Funciona offline e suas chaves privadas permanecem no aparelho.',
        style: Theme.of(context).textTheme.bodyLarge,
      ),
      const SizedBox(height: 20),
      const Card(
        child: ListTile(
          leading: Icon(Icons.warning_amber),
          title: Text('Passkeys ainda não têm backup'),
          subtitle: Text(
            'Mantenha outro método de acesso em cada site antes de criar uma passkey.',
          ),
        ),
      ),
    ],
  );
}
