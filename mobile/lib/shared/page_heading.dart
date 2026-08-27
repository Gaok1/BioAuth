import 'package:flutter/material.dart';

class PageHeading extends StatelessWidget {
  const PageHeading({required this.title, this.subtitle, super.key});

  final String title;
  final String? subtitle;

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    return Padding(
      padding: const EdgeInsets.fromLTRB(20, 24, 20, 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: textTheme.headlineMedium),
          if (subtitle case final subtitle?) ...[
            const SizedBox(height: 6),
            Text(subtitle, style: textTheme.bodyMedium),
          ],
        ],
      ),
    );
  }
}
