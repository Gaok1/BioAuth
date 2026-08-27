import 'package:flutter/material.dart';

import '../domain/authentication_request.dart';

class AuthenticationRequestCard extends StatelessWidget {
  const AuthenticationRequestCard({
    required this.request,
    required this.onTap,
    super.key,
  });

  final AuthenticationRequest request;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: InkWell(
        borderRadius: BorderRadius.circular(18),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            children: [
              const CircleAvatar(child: Icon(Icons.login)),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      request.deviceName,
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    Text('${request.service} • ${request.resource}'),
                    if (request.duplicateCount > 1)
                      Text(
                        '${request.duplicateCount} solicitações iguais agrupadas',
                        style: TextStyle(
                          color: Theme.of(context).colorScheme.error,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                  ],
                ),
              ),
              const Icon(Icons.chevron_right),
            ],
          ),
        ),
      ),
    );
  }
}
