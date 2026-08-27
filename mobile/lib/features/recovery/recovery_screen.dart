import 'package:flutter/material.dart';

class RecoveryScreen extends StatelessWidget {
  const RecoveryScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Recuperação')),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          Icon(
            Icons.phonelink_erase,
            size: 64,
            color: Theme.of(context).colorScheme.primary,
          ),
          const SizedBox(height: 20),
          Text(
            'Perdeu o telefone?',
            style: Theme.of(context).textTheme.headlineSmall,
          ),
          const SizedBox(height: 10),
          const Text(
            'Remova este telefone em cada computador pareado. Um novo aparelho '
            'deve criar sua própria chave e ser pareado novamente.',
          ),
          const SizedBox(height: 20),
          const Card(
            child: Padding(
              padding: EdgeInsets.all(16),
              child: Text(
                'Chaves privadas não são exportadas nem incluídas em backup.',
              ),
            ),
          ),
        ],
      ),
    );
  }
}
