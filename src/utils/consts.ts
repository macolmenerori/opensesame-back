export type HTTPMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';

export const escapeRegExp = (input: string) => {
  return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); // $& means the whole matched string
};
