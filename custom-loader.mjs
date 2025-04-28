export async function resolve(specifier, context, defaultResolve) {
  try {
    return await defaultResolve(specifier, context, defaultResolve);
  } catch (err) {
    // Handle bare directory imports by appending "/index.js"
    if (err.code === 'ERR_UNSUPPORTED_DIR_IMPORT') {
      return defaultResolve(specifier + '/index.js', context, defaultResolve);
    }
    // Handle missing modules that may be missing the .js extension
    if (err.code === 'ERR_MODULE_NOT_FOUND' && !specifier.endsWith('.js')) {
      return defaultResolve(specifier + '.js', context, defaultResolve);
    }
    throw err;
  }
}

export async function load(url, context, defaultLoad) {
  // If the file is a JSON and lacks an import assertion, add it.
  if (url.endsWith('.json')) {
    const newContext = {
      ...context,
      importAssertions: { type: 'json' },
    };
    return defaultLoad(url, newContext, defaultLoad);
  }
  return defaultLoad(url, context, defaultLoad);
}
